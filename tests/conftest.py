"""Pytest fixture for the openvas agent."""
import pytest

from ostorlab.agent import message


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.ip to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
            'host': '209.235.136.112',
            'mask': '32',
            'version': 4
        }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_link():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.link'
    msg_data = {
            'url': 'https://test.ostorlab.co',
            'method': 'GET'
        }
    return message.Message.from_data(selector, data=msg_data)
