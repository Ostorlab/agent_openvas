"""Sample agent implementation"""
import csv
import json
import logging
import subprocess
import time
from urllib import parse
import ipaddress
from typing import Dict, Optional
import re

from ostorlab.agent import agent
from ostorlab.agent.message import message as m
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from rich import logging as rich_logging

from agent import openvas
from agent import targetables


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
        self._scope_regex: Optional[str] = self.args.get('scope_regex')

    def start(self) -> None:
        """Calls the start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT, check=True)
        self._wait_vt_ready()
        logger.info('vt is ready')

    def process(self, message: m.Message) -> None:
        logger.info('processing message from selector %s', message.selector)
        openvas_wrapper = openvas.OpenVas()

        target = None

        if message.data.get('name') is not None:
            target = self._prepare_target_from_domain_msg(message)
            if not self.set_add(STORAGE_NAME, target.name):
                logger.info('target %s was processed before, exiting', target.name)
                return

        elif message.data.get('url') is not None:
            target = self._prepare_target_from_link_msg(message)
            if not self.set_add(STORAGE_NAME, target.name):
                logger.info('target %s was processed before, exiting', target.name)
                return

        elif message.data.get('host') is not None:
            target = self._prepare_target_from_ip_msg(message)
            addresses = ipaddress.ip_network(target.name, strict=False)
            if not self.add_ip_network(STORAGE_NAME, addresses):
                logger.info('target %s was processed before, exiting', target.name)
                return
        else:
            logger.info('Target not provided')
            return

        url_in_scope = self._is_url_in_scan_scope(target.name, self._scope_regex)
        if isinstance(target, targetables.DomainTarget) and url_in_scope is False:
            return

        logger.info('scanning target %s', target.name)
        task_id = openvas_wrapper.start_scan(target.name,
                                             self.args.get('scan_config_id', openvas.GVMD_FULL_FAST_CONFIG))
        openvas_wrapper.wait_task(task_id)
        result = openvas_wrapper.get_results()
        if result is not None:
            self._persist_results(result)
            self._process_results(target)
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

    def _get_vulnerable_target_data(self,
                                    target: targetables.DomainTarget | targetables.IPTarget,
                                    vuln: Dict[str, str]
                                    ) -> Optional[agent_report_vulnerability_mixin.VulnerabilityLocation]:
        """Returns the exact target where the vulnerability was detected,
        eg: In which IP of the given range the vulnerability was found."""
        metadata = []
        if vuln.get('Port', '') != '':
            metadata_type = agent_report_vulnerability_mixin.MetadataType.PORT
            metadata_value = vuln.get('Port')
            metadata = [
                agent_report_vulnerability_mixin.VulnerabilityLocationMetadata(type=metadata_type, value=metadata_value)
            ]
        if isinstance(target, targetables.DomainTarget) and vuln.get('Hostname', '') != '':
            asset = domain_asset.DomainName(name=vuln.get('Hostname'))
            return agent_report_vulnerability_mixin.VulnerabilityLocation(asset=asset, metadata=metadata)
        elif isinstance(target, targetables.IPTarget) and vuln.get('IP', '') != '':
            vulnerable_host = vuln.get('IP')
            if target.version==4:
                asset = ipv4_asset.IPv4(host = vulnerable_host, version = 4, mask = '32')
            else:
                asset = ipv6_asset.IPv6(host = vulnerable_host, version = 6, mask = '128')
            return agent_report_vulnerability_mixin.VulnerabilityLocation(asset=asset, metadata=metadata)
        else:
            raise NotImplementedError(f'type target {type(target)} not implemented')


    def _process_results(self, target: targetables.DomainTarget | targetables.IPTarget):
        """read and parse the output file and send the findings"""

        with open(CSV_PATH_OUTPUT, encoding='UTF-8') as csv_file:
            line_results = csv.DictReader(csv_file)
            for line_result in line_results:
                detail = line_result.get('Specific Result', '')
                detail += '\n'
                detail += f'```json\n{json.dumps(line_result, indent=4, sort_keys=True)}\n```'
                vulnerability_location = self._get_vulnerable_target_data(target, line_result)
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
                    risk_rating=_severity_map(line_result.get('severity', 'INFO').lower()),
                    vulnerability_location=vulnerability_location)


    def _is_url_in_scan_scope(self, url: str, scope_regex: Optional[str] = None) -> bool:
        if scope_regex is None:
            return True
        if re.match(scope_regex, url) is None:
            logger.warning('link url %s is not in domain %s', url, scope_regex)
            return False
        else:
            return True

    def _prepare_target_from_domain_msg(self, message: m.Message) -> targetables.DomainTarget:
        domain_name = message.data.get('name', '')
        return targetables.DomainTarget(name=domain_name)

    def _prepare_target_from_link_msg(self, message: m.Message) -> targetables.DomainTarget:
        domain_name = parse.urlparse(message.data.get('url')).netloc
        return targetables.DomainTarget(name=domain_name)

    def _prepare_target_from_ip_msg(self, message: m.Message) -> targetables.IPTarget:
        host = message.data.get('host')
        version = ipaddress.ip_address(host).version
        default_mask = '32' if version == 4 else '128'
        mask = message.data.get('mask', default_mask)
        if mask == default_mask:
            target = targetables.IPTarget(name=host, version=version)
        else:
            target = targetables.IPTarget(name=f'{host}/{mask}', version=version, mask=mask)
        return target


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
