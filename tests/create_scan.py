# https://github.com/chensandiego/openvas_py/tree/27cddae833a6fe3dda7e83c47151ed127c879022
"""
it uses openvas and python to scan

1:create a docker image and start the openvas container docker volume create openvas

docker run -d -p 9392:9392 -p 9390:9390 -e GMP=9390 -e PASSWORD=”admin” --volume openvas:/data --name openvas immauss/openvas:latest 2. install python-gvm

fire up the program python vulscan.py A. it scan localhost for the demo. It will need to change for the target scaned system
"""

import gvm
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
import datetime

def create_target(gmp, ipaddress, port_list_id):
    # create a unique name by adding the current datetime
    name = "Suspect Host {} {}".format(ipaddress, str(datetime.datetime.now()))
    response = gmp.create_target(
        name=name, hosts=[ipaddress], port_list_id=port_list_id
    )
    return response.get('id')


def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def create_task(gmp, ipaddress, target_id, scan_config_id, scanner_id):
    name = "Scan Suspect Host {}".format(ipaddress)
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get('id')


def main():
    ipaddress = "8.8.8.8"
    # ex. iana-tcp-udp scan
    port_list_id = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
    connection = gvm.connections.TLSConnection(hostname='localhost')
    transform = EtreeTransform()
    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')
        target_id = create_target(gmp, ipaddress, port_list_id)
        full_and_fast_scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea'
        openvas_scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'
        task_id = create_task(
            gmp,
            ipaddress,
            target_id,
            full_and_fast_scan_config_id,
            openvas_scanner_id,
        )
        report_id = start_task(gmp, task_id)
        print(
            "Started scan of host {}. Corresponding report ID is {}".format(
                ipaddress, report_id
            )
        )


if __name__ == "__main__":
    main()