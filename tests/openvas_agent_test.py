"""Unittests for OpenVas class."""
import json

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import openvas_agent


def testAgentOpenVas_whenBinaryAvailable_RunScan(scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    definition = agent_definitions.AgentDefinition(
        name='start_test_agent',
        out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/start_test_agent',
        bus_url='NA',
        bus_exchange_topic='NA',
        args=[
            utils_definitions.Arg(name='reporting_engine_base_url', type='str', value=b'https://toto.ostorlab.co/test'),
            utils_definitions.Arg(name='reporting_engine_token', type='str', value=b'123456')],
        healthcheck_port=5301)
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        test_agent = openvas_agent.OpenVasAgent(definition, settings)
        test_agent.process(scan_message)

        output = {'IP': '128.0.0.1', 'Hostname': 'test', 'Port': '', 'Port Protocol': '', 'CVSS': '',
                  'Severity': 'HIGH', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                  'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                  'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                  'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                  'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}

        mock_report_vulnerability.assert_called_with(entry=kb.Entry(title='', risk_rating='INFO',
                                                                    references={}, short_description='',
                                                                    description='', recommendation='',
                                                                    security_issue=True, privacy_issue=False,
                                                                    has_public_exploit=False,
                                                                    targeted_by_malware=False,
                                                                    targeted_by_ransomware=False,
                                                                    targeted_by_nation_state=False,
                                                                    cvss_v3_vector=''),
                                                     risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO,
                                                     technical_detail=
                                                     f'\n```json\n{json.dumps(output, indent=4, sort_keys=True)}\n```')


def testAgentOpenVas_whenLinkAssetAndBinaryAvailable_RunScan(scan_message_link, mocker):
    """Tests running the agent and parsing the json output."""
    definition = agent_definitions.AgentDefinition(
        name='start_test_agent',
        out_selectors=['v3.report.vulnerability'])
    settings = runtime_definitions.AgentSettings(
        key='agent/ostorlab/start_test_agent',
        bus_url='NA',
        bus_exchange_topic='NA',
        args=[
            utils_definitions.Arg(name='reporting_engine_base_url', type='str', value=b'https://toto.ostorlab.co/test'),
            utils_definitions.Arg(name='reporting_engine_token', type='str', value=b'123456')],
        healthcheck_port=5301)
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        test_agent = openvas_agent.OpenVasAgent(definition, settings)
        test_agent.process(scan_message_link)

        output = {'IP': '128.0.0.1', 'Hostname': 'test', 'Port': '', 'Port Protocol': '', 'CVSS': '',
                  'Severity': 'HIGH', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                  'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                  'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                  'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                  'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}

        mock_report_vulnerability.assert_called_with(entry=kb.Entry(title='', risk_rating='INFO',
                                                                    references={}, short_description='',
                                                                    description='', recommendation='',
                                                                    security_issue=True, privacy_issue=False,
                                                                    has_public_exploit=False,
                                                                    targeted_by_malware=False,
                                                                    targeted_by_ransomware=False,
                                                                    targeted_by_nation_state=False,
                                                                    cvss_v3_vector=''),
                                                     risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO,
                                                     technical_detail=
                                                     f'\n```json\n{json.dumps(output, indent=4, sort_keys=True)}\n```')
