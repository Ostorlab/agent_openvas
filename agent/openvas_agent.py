"""Sample agent implementation"""
import logging
import subprocess
import time

from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.kb import kb

from agent import openvas

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')

START_SCRIPT = '/start.sh'
LOG_FILE = '/usr/local/var/log/gvm/gvmd.log'
VT_CHECK = b'Updating VTs in database ... done'
WAIT_VT_LOAD = 30

class OpenVasAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """OpenVas Agent."""

    def start(self) -> None:
        """Calls that start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT, check=True)
        self._wait_vt_ready()

    def process(self, message: m.Message) -> None:
        logger.info('processing message')
        openvas_wrapper = openvas.OpenVas()
        task_id = openvas_wrapper.start_scan(message.data.get('host'))
        openvas_wrapper.wait_task(task_id)
        result = openvas_wrapper.get_results()
        self._send_results(result)
        logger.info('Scan finished.')

    def _wait_vt_ready(self):
        while True:
            with open(LOG_FILE, 'rb') as f:
                for line in f.readlines():
                    if VT_CHECK in line:
                        return True
            logger.info('Waiting for VT to load in database.')
            time.sleep(WAIT_VT_LOAD)

    def _send_results(self, results):
        self.report_vulnerability(
            entry=kb.Entry(
                title='openvas',
                risk_rating='INFO',
                short_description='',
                description='',
                recommendation='',
                references={},
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False
            ),
            technical_detail=f'```json\n{results}\n```',
            risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
