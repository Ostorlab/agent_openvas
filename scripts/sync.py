from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

connection = TLSConnection(hostname='127.0.0.1', port=9390)
transform = EtreeTransform()

with Gmp(connection, transform=transform) as gmp:
    # Retrieve GMP version supported by the remote daemon
    version = gmp.get_version()

    # Prints the XML in beautiful form
    pretty_print(version)

    # Login
    gmp.authenticate('admin', 'admin')

    # Retrieve all tasks
    tasks = gmp.get_tasks()

    # Get names of tasks
    task_names = tasks.xpath('task/name/text()')
    pretty_print(task_names)
