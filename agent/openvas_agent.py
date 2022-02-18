"""Sample agent implementation"""
import logging
import subprocess

from ostorlab.agent import agent
from ostorlab.agent import message as m
from rich import logging as rich_logging
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from agent import openvas

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)

START_SCRIPT = '/start.sh'


class OpenVasAgent(agent.Agent,  agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """OpenVas Agent."""

    def start(self) -> None:
        """Calls that start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT)

    def process(self, message: m.Message) -> None:
        """Start a full scan and reports identified vulnerabilities.

        Args:
            message: IP message.
        """
        # TODO (author): implement agent logic here.
        client = openvas.OpenVas()
        scan_id = client.start_scan(message.data['host'])
        # wait for the scan to complete.
        client.wait_scan(scan_id)
        scan_result = client.get_results(scan_id)
        for vulnerability in scan_result['vulnerabilities']:
            # risk_rating will be HIGH for all detected vulnerabilities
            risk_rating = 'HIGH'
            self.report_vulnerability(
                entry=kb.Entry(
                    title=vulnerability['vulnerability']['title'],
                    risk_rating=risk_rating,
                    short_description=vulnerability['vulnerability']['description'],
                    description=vulnerability['vulnerability']['description'],
                    recommendation='',
                    references={},
                    security_issue=True,
                    privacy_issue=False,
                    has_public_exploit=True,
                    targeted_by_malware=True,
                    targeted_by_ransomware=True,
                    targeted_by_nation_state=True
                ),
                technical_detail=f'```json\n{scan_result}\n```',
                risk_rating=risk_rating)
        logger.info('Scan finished Number of finding %s', len(scan_result['vulnerabilities']))


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
