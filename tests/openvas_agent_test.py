"""Unittests for OpenVas class."""
import json

from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin


def testAgentOpenVas_whenBinaryAvailable_RunScan(openvas_agent_no_scope, scan_message, mocker):
    """Tests running the agent and parsing the json output."""
    star_scan_mocker = mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        openvas_agent_no_scope.process(scan_message)

        output = {'IP': '128.0.0.1', 'Hostname': 'test', 'Port': '', 'Port Protocol': '', 'CVSS': '',
                  'Severity': 'HIGH', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                  'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                  'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                  'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                  'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}

        star_scan_mocker.assert_called_with(scan_message.data.get('host'), None)
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


def testAgentOpenVas_whenLinkAssetAndBinaryAvailable_RunScan(openvas_agent, scan_message_link, mocker):
    """Tests running the agent and parsing the json output."""
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        openvas_agent.process(scan_message_link)

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


def testAgentOpenVas_whenLinkAssetGiven_NotScan(openvas_agent, scan_message_link_2, mocker):
    """Tests running the agent and parsing the json output."""
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        _run_command_mock = mocker.patch('subprocess.run', return_value=None)
        openvas_agent.process(scan_message_link_2)
        _run_command_mock.assert_not_called()


def testAgentOpenVas_whenServiceAssetGiven_RunScan(openvas_agent, scan_message_service, mocker):
    """Tests running the agent and parsing the json output."""
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        openvas_agent.process(scan_message_service)

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


def testAgentOpenVas_whenDomainNameAssetGiven_NotScan(openvas_agent,
                                                      scan_message_domain_2,
                                                      mocker):
    """Tests running the agent and parsing the json output."""
    mocker.patch('agent.openvas.OpenVas.start_scan', return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        _run_command_mock = mocker.patch('subprocess.run', return_value=None)
        openvas_agent.process(scan_message_domain_2)
        _run_command_mock.assert_not_called()


def testAgentOpenVas_whenBinaryAvailableAndRangeOfIPsIsInput_RunScan(
        openvas_agent_no_scope,
        ip_range_message,
        mocker):
    """Tests running the agent and parsing the json output for an IP range."""
    star_scan_mocker = mocker.patch('agent.openvas.OpenVas.start_scan', return_value='starting scan..')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/ip_range_openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        openvas_agent_no_scope.process(ip_range_message)
        output1 = {'IP': '128.0.0.1', 'Hostname': 'hostname1', 'Port': '80', 'Port Protocol': '', 'CVSS': '',
                   'Severity': 'HIGH', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                   'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                   'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                   'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                   'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}
        args1 = {
            'entry': kb.Entry(title='', risk_rating='INFO',
                              references={}, short_description='',
                              description='', recommendation='',
                              security_issue=True, privacy_issue=False,
                              has_public_exploit=False,
                              targeted_by_malware=False,
                              targeted_by_ransomware=False,
                              targeted_by_nation_state=False,
                              cvss_v3_vector=''),
            'risk_rating': agent_report_vulnerability_mixin.RiskRating.INFO,
            'technical_detail': f'\n```json\n{json.dumps(output1, indent=4, sort_keys=True)}\n```'
        }

        output2 = {'IP': '128.0.0.2', 'Hostname': 'hostname2', 'Port': '443', 'Port Protocol': '', 'CVSS': '',
                   'Severity': 'LOW', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                   'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                   'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                   'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                   'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}
        args2 = {
            'entry': kb.Entry(title='', risk_rating='INFO',
                              references={}, short_description='',
                              description='', recommendation='',
                              security_issue=True, privacy_issue=False,
                              has_public_exploit=False,
                              targeted_by_malware=False,
                              targeted_by_ransomware=False,
                              targeted_by_nation_state=False,
                              cvss_v3_vector=''),
            'risk_rating': agent_report_vulnerability_mixin.RiskRating.INFO,
            'technical_detail': f'\n```json\n{json.dumps(output2, indent=4, sort_keys=True)}\n```'
        }

        assert mock_report_vulnerability.call_count == 2

        assert mock_report_vulnerability.call_args_list[0].kwargs == args1
        assert mock_report_vulnerability.call_args_list[1].kwargs == args2
        star_scan_mocker.assert_called_with(
            f'{ip_range_message.data.get("host")}/{ip_range_message.data.get("mask")}', None)


def testAgentOpenVas_whenBinaryAvailableAndRangeOfIPsIsInput_NotScan(openvas_agent_no_scope,
                                                                     ip_range_message,
                                                                     mocker):
    """Tests running the agent and parsing the json output for an IP range."""
    star_scan_mocker = mocker.patch('agent.openvas.OpenVas.start_scan', return_value='starting scan..')
    mocker.patch('agent.openvas.OpenVas.wait_task', return_value=None)
    with open('tests/ip_range_openvas_result.csv', 'r', encoding='UTF-8') as f:
        mocker.patch('agent.openvas.OpenVas.get_results', return_value=f.read())
        mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability',
                                                 return_value=None)
        openvas_agent_no_scope.process(ip_range_message)
        output1 = {'IP': '128.0.0.1', 'Hostname': 'hostname1', 'Port': '80', 'Port Protocol': '', 'CVSS': '',
                   'Severity': 'HIGH', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                   'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                   'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                   'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                   'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}
        args1 = {
            'entry': kb.Entry(title='', risk_rating='INFO',
                              references={}, short_description='',
                              description='', recommendation='',
                              security_issue=True, privacy_issue=False,
                              has_public_exploit=False,
                              targeted_by_malware=False,
                              targeted_by_ransomware=False,
                              targeted_by_nation_state=False,
                              cvss_v3_vector=''),
            'risk_rating': agent_report_vulnerability_mixin.RiskRating.INFO,
            'technical_detail': f'\n```json\n{json.dumps(output1, indent=4, sort_keys=True)}\n```'
        }

        output2 = {'IP': '128.0.0.2', 'Hostname': 'hostname2', 'Port': '443', 'Port Protocol': '', 'CVSS': '',
                   'Severity': 'LOW', 'Solution Type': '', 'NVT Name': '', 'Summary': '', 'Specific Result': '',
                   'NVT OID': '', 'CVEs': '', 'Task ID': '', 'Task Name': 'PRODUCT_TEST_ONLY',
                   'Timestamp': '2018-03-21T10:19:16+08:00', 'Result ID': '', 'Impact': '', 'Solution': '',
                   'Affected Software/OS': '', 'Vulnerability Insight': '', 'Vulnerability Detection Method': '',
                   'Product Detection Result': '', 'BIDs': '', 'CERTs': '', 'Other References': ''}
        args2 = {
            'entry': kb.Entry(title='', risk_rating='INFO',
                              references={}, short_description='',
                              description='', recommendation='',
                              security_issue=True, privacy_issue=False,
                              has_public_exploit=False,
                              targeted_by_malware=False,
                              targeted_by_ransomware=False,
                              targeted_by_nation_state=False,
                              cvss_v3_vector=''),
            'risk_rating': agent_report_vulnerability_mixin.RiskRating.INFO,
            'technical_detail': f'\n```json\n{json.dumps(output2, indent=4, sort_keys=True)}\n```'
        }

        assert mock_report_vulnerability.call_count == 2

        assert mock_report_vulnerability.call_args_list[0].kwargs == args1
        assert mock_report_vulnerability.call_args_list[1].kwargs == args2
        star_scan_mocker.assert_called_with(
            f'{ip_range_message.data.get("host")}/{ip_range_message.data.get("mask")}', None)
