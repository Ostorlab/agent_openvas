"""Sample agent implementation"""
import csv
import json
import logging
import subprocess
import time

from ostorlab.agent import agent
from ostorlab.agent import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

from agent import openvas

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

START_SCRIPT = '/start.sh'
LOG_FILE = '/usr/local/var/log/gvm/gvmd.log'
VT_CHECK = b'Updating VTs in database ... done'
WAIT_VT_LOAD = 30
CSV_PATH_OUTPUT = '/tmp/csvFilePath.csv'


def _severity_map(severity: str) -> agent_report_vulnerability_mixin.RiskRating:
    if severity == 'log':
        return agent_report_vulnerability_mixin.RiskRating.INFO
    elif severity == 'low':
        return agent_report_vulnerability_mixin.RiskRating.LOW
    elif severity == 'medium':
        return agent_report_vulnerability_mixin.RiskRating.MEDIUM
    elif severity == 'high':
        return agent_report_vulnerability_mixin.RiskRating.HIGH
    else:
        logger.warning('Unknown severity level %s, defaulting to INFO', severity)
        return agent_report_vulnerability_mixin.RiskRating.INFO


class OpenVasAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """OpenVas Agent."""

    def start(self) -> None:
        """Calls the start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT, check=True)
        self._wait_vt_ready()
        logger.info('vt is ready')

    def process(self, message: m.Message) -> None:
        logger.info('processing message from selector %s', message.selector)
        openvas_wrapper = openvas.OpenVas()
        target = message.data.get('name') or message.data.get('host')
        logger.info('scanning target %s', target)
        task_id = openvas_wrapper.start_scan(target)
        openvas_wrapper.wait_task(task_id)
        result = openvas_wrapper.get_results()
        self._persist_results(result)
        self._process_results()
        logger.info('Scan finished.')

    def _wait_vt_ready(self):
        """when started, Openvas first loads all the VT to the database
        We need to wait until the load is done before processing the message
        """
        while True:
            with open(LOG_FILE, 'rb') as f:
                for line in f.readlines():
                    if VT_CHECK in line:
                        return True
            logger.info('Waiting for VT to load in database.')
            time.sleep(WAIT_VT_LOAD)

    def _persist_results(self, results: str):
        """Persist the csv result file
        Args:
            results: file content
        """
        with open(CSV_PATH_OUTPUT, 'w', encoding='UTF-8') as f:
            f.write(results)

    def _process_results(self):
        """read and parse the output file and send the findings"""

        with open(CSV_PATH_OUTPUT, encoding='UTF-8') as csv_file:
            line_results = csv.DictReader(csv_file)
            for line_result in line_results:
                detail = line_result.get('Specific Result', '')
                detail += '\n'
                detail += f'```json\n{json.dumps(line_result, indent=4, sort_keys=True)}\n```'
                self.report_vulnerability(
                    entry=kb.Entry(
                        title=line_result.get('NVT Name', 'OpenVas Finding'),
                        risk_rating=_severity_map(line_result.get('severity', 'INFO').lower()).name,
                        cvss_v3_vector=line_result.get('CVSS', ''),
                        short_description=line_result.get('Summary', ''),
                        description=line_result.get('Summary', '') + line_result.get('Vulnerability Insight', ''),
                        recommendation=line_result.get('Solution', ''),
                        references={},
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False
                    ),
                    technical_detail=detail,
                    risk_rating=_severity_map(line_result.get('severity', 'INFO').lower()))


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
