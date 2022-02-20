"""Sample agent implementation"""
import logging
import subprocess

from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as m

from agent import openvas

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')

START_SCRIPT = '/app/agent/scripts/start.sh'


class OpenVasAgent(agent.Agent):
    """OpenVas Agent."""

    def start(self) -> None:
        """Calls that start.sh script to bootstrap the scanner."""
        logger.info('starting openvas daemons')
        subprocess.run(START_SCRIPT)

    def process(self, message: m.Message) -> None:
        logger.info('processing message')
        openVas = openvas.OpenVas()
        openVas.start_scan(message.data.get('host'))
        openVas.OpenVas.wait_task()
        openVas.OpenVas.get_results()


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
