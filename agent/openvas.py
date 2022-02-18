import datetime

import gvm
from gvm.protocols import gmp as openvas_gmp
from gvm import transforms

ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
GVMD_FULL_FAST_CONFIG = 'daba56c8-73ec-11df-a475-002264764cea'
OPENVAS_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
GMP_USERNAME = 'admin'
GMP_PASSWORD = 'admin'


class OpenVas:

    def start_scan(self, ip):

        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            target_id = self._create_target(gmp, ip, ALL_IANA_ASSIGNED_TCP_UDP)
            task_id = self._create_task(
                gmp,
                ip,
                target_id,
                GVMD_FULL_FAST_CONFIG,
                OPENVAS_SCANNER_ID,
            )
            report_id = self._start_task(gmp, task_id)
            print(
                "Started scan of host {}. Corresponding report ID is {}".format(
                    ip, report_id
                )
            )

    def _create_target(self, gmp, ip_address, port_list_id):
        name = "Testing Host {} {}".format(ip_address, str(datetime.datetime.now()))
        response = gmp.create_target(name=name, hosts=[ip_address], port_list_id=port_list_id)
        return response.get('id')

    def _start_task(self, gmp, task_id):
        response = gmp.start_task(task_id)
        return response[0].text

    def _create_task(self, gmp, ip_address, target_id, scan_config_id, scanner_id):
        name = "Scan Host {}".format(ip_address)
        response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id,)
        return response.get('id')