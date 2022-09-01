"""Pytest fixture for the openvas agent."""
import pytest
import pathlib

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import openvas_agent


@pytest.fixture(scope='function', name='openvas_agent')
def fixture_agent(agent_mock, agent_persist_mock):
    """OpenVasAgent fixture for testing purposes."""
    del agent_mock
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/openvas',
            bus_url='NA',
            bus_exchange_topic='NA',
            args=[
                utils_definitions.Arg(
                    name='reporting_engine_base_url',
                    type='string',
                    value='https://toto.ostorlab.co/test',
                ),
                utils_definitions.Arg(
                    name='reporting_engine_token', type='string', value='123456'
                ),
            ],
            healthcheck_port=5301,
            redis_url='redis://guest:guest@localhost:6379'
        )

        agent = openvas_agent.OpenVasAgent(definition, settings)
        return agent


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.ip to be used by the agent for testing purposes."""
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '209.235.136.112',
        'mask': '32',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = 'v3.asset.link'
    msg_data = {
        'url': 'https://test.ostorlab.co',
        'method': 'GET'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def ip_range_message():
    """Creates a dummy message of type v3.asset.ip with a /31 mask to be used by the agent for testing purposes."""
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '128.0.0.1',
        'mask': '31',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)
