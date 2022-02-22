"""Unittests for nuclei class."""
from unittest import mock

from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin

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
    mocker.patch('agent.openvas.OpenVas.start_scan',return_value='hduzehfuhehfuhef')
    mocker.patch('agent.openvas.OpenVas.wait_task',return_value=None)
    mocker.patch('agent.openvas.OpenVas.get_results',return_value='xml_result')
    mock_report_vulnerability = mocker.patch('agent.openvas_agent.OpenVasAgent.report_vulnerability', return_value=None)
    test_agent = openvas_agent.OpenVasAgent(definition, settings)
    test_agent.process(scan_message)
    mock_report_vulnerability.assert_called()