"""Sample agent implementation"""
import logging
import subprocess

from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as m

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
        """TODO (author): add your description here.

        Args:
            message:

        Returns:

        """
        # TODO (author): implement agent logic here.
        del message
        logger.info('processing message')
        self.emit('v3.healthcheck.ping', {'body': 'Hello World!'})


if __name__ == '__main__':
    logger.info('starting agent ...')
    OpenVasAgent.main()
