"""Pytest fixture for the openvas agent."""

import json
from typing import List, Dict

import pytest
import pathlib

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import openvas_agent


@pytest.fixture(scope="function", name="openvas_agent")
def fixture_agent(agent_mock, agent_persist_mock):
    """OpenVasAgent fixture for testing purposes."""
    del agent_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        definition.args[0]["value"] = "ostorlab.co"
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/openvas",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="reporting_engine_base_url",
                    type="string",
                    value=json.dumps("https://toto.ostorlab.co/test").encode(),
                ),
                utils_definitions.Arg(
                    name="reporting_engine_token",
                    type="string",
                    value=json.dumps("123456").encode(),
                ),
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = openvas_agent.OpenVasAgent(definition, settings)
        return agent


@pytest.fixture(scope="function", name="openvas_agent_no_scope")
def fixture_agent_no_scope(agent_mock, agent_persist_mock):
    """OpenVasAgent fixture for testing purposes."""
    del agent_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/openvas",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="reporting_engine_base_url",
                    type="string",
                    value=json.dumps("https://toto.ostorlab.co/test").encode(),
                ),
                utils_definitions.Arg(
                    name="reporting_engine_token",
                    type="string",
                    value=json.dumps("123456").encode(),
                ),
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = openvas_agent.OpenVasAgent(definition, settings)
        return agent


@pytest.fixture(scope="function", name="openvas_agent_with_scope")
def fixture_agent_with_scope_arg(
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> openvas_agent.OpenVasAgent:
    """OpenVasAgent fixture for testing purposes."""
    del agent_mock, agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/openvas",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[
                utils_definitions.Arg(
                    name="reporting_engine_base_url",
                    type="string",
                    value=json.dumps("https://toto.ostorlab.co/test").encode(),
                ),
                utils_definitions.Arg(
                    name="reporting_engine_token",
                    type="string",
                    value=json.dumps("123456").encode(),
                ),
                utils_definitions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
            healthcheck_port=5301,
            redis_url="redis://guest:guest@localhost:6379",
        )

        agent = openvas_agent.OpenVasAgent(definition, settings)
        return agent


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.ip to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "209.235.136.112", "mask": "32", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link():
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://ostorlab.co", "method": "GET"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link_2():
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://test.ostorlab.co", "method": "GET"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_service() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"name": "ostorlab.co", "port": 3000, "schema": "https"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_domain_2() -> message.Message:
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name.service"
    msg_data = {"name": "lab.co"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def ip_range_message():
    """Creates a dummy message of type v3.asset.ip with a /31 mask to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "128.0.0.1", "mask": "31", "version": 4}
    return message.Message.from_data(selector, data=msg_data)
