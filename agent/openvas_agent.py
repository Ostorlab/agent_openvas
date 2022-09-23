"""Sample agent implementation"""
import csv
import json
import logging
import subprocess
import time
from urllib import parse
import ipaddress
from typing import Optional, Union
import re

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import openvas

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

START_SCRIPT = '/scripts/start.sh'
LOG_FILE = '/usr/local/var/log/gvm/gvmd.log'
VT_CHECK = b'Updating VTs in database ... done'
WAIT_VT_LOAD = 30
CSV_PATH_OUTPUT = '/tmp/csvFilePath.csv'
STORAGE_NAME = 'agent_openvas_asset'


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


class OpenVasAgent(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin):
    """OpenVas Agent."""

    def __init__(self,
                 agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings
                 ) -> None:
        super().__init__(agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_urls_regex: Optional[str] = self.args.get('scope_urls_regex')

    def start(self) -> None:
        """Calls the start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT, check=True)
        self._wait_vt_ready()
        logger.info('vt is ready')

    def process(self, message: m.Message) -> None:
        logger.info('processing message from selector %s', message.selector)
        openvas_wrapper = openvas.OpenVas()
        target = self._prepare_target(message)
        if target is None:
            return
        else:
            logger.info('scanning target %s', target)
            task_id = openvas_wrapper.start_scan(target)
            openvas_wrapper.wait_task(task_id)
            result = openvas_wrapper.get_results()
            if result is not None:
                self._persist_results(result)
                self._process_results()
            logger.info('Scan finished.')

    def _prepare_target(self, message: m.Message) -> str:
        """Prepare targets based on type, if a domain name is provided, port and protocol are collected from the config.
        """
        if (target := message.data.get('name')) is not None:
            schema = self._get_schema(message)
            port = message.data.get('port')
            if schema == 'https' and port not in [443, None]:
                url = f'https://{target}:{port}'
            elif schema == 'https':
                url = f'https://{target}'
            elif port == 80:
                url = f'http://{target}'
            elif port is None:
                url = f'{schema}://{target}'
            else:
                url = f'{schema}://{target}:{port}'
            return self._prepare_domain_target(message) if \
                self._should_process_target(self._scope_urls_regex, url) else None
        elif message.data.get('host'):
            target = self._prepare_ip_target(message)
            return target
        elif message.data.get('url') is not None:
            return self._prepare_url_target(message) if \
                self._should_process_target(self._scope_urls_regex, str(message.data.get('url'))) else None

    def _prepare_domain_target(self, message: m.Message) -> Union[str, None]:
        """Prepares and checks if a domain asset has been processed before."""
        target = message.data.get('name')
        if not self.set_add(STORAGE_NAME, target):
            logger.info('target %s was processed before, exiting', target)
            return None
        else:
            return target

    def _prepare_url_target(self, message: m.Message) -> Union[str, None]:
        """Prepares and checks if an URL asset has been processed before."""
        target = parse.urlparse(message.data.get('url')).netloc
        if not self.set_add(STORAGE_NAME, target):
            logger.info('target %s was processed before, exiting', target)
            return None
        else:
            return target

    def _prepare_ip_target(self, message: m.Message) -> str:
        """Prepares and checks if an IP or a range of IPs assets has been processed before."""
        host = message.data.get('host')
        version = ipaddress.ip_address(host).version
        default_mask = '32' if version == 4 else '164'
        mask = message.data.get('mask', default_mask)
        if mask == default_mask:
            target = host
        else:
            target = f'{host}/{mask}'
        addresses = ipaddress.ip_network(target, strict=False)
        if not self.add_ip_network(STORAGE_NAME, addresses):
            logger.info('target %s was processed before, exiting', target)
        else:
            return target

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

    def _should_process_target(self, scope_urls_regex: Optional[str], url: str) -> bool:
        if scope_urls_regex is None:
            return True
        link_in_scan_domain = re.match(scope_urls_regex, url) is not None
        if not link_in_scan_domain:
            logger.warning('link url %s is not in domain %s', url, scope_urls_regex)
        return link_in_scan_domain

    def _get_schema(self, message: m.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get('schema') is not None:
            return str(message.data['schema'])
        elif message.data.get('protocol') is not None:
            return str(message.data['protocol'])
        elif self.args.get('https') is True:
            return 'https'
        else:
            return 'http'


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
