"""Wrapper for OpenVas scanner to start the scan and extract the results."""
import datetime
import logging

import gvm
from gvm.protocols import gmp as openvas_gmp
from gvm import transforms

logger = logging.getLogger(__name__)

ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
GVMD_FULL_FAST_CONFIG = 'daba56c8-73ec-11df-a475-002264764cea'
OPENVAS_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
GMP_USERNAME = 'admin'
GMP_PASSWORD = 'admin'


class OpenVas:
    """OpenVas wrapper to enable using openvas scanner from ostorlab agent class."""
    def start_scan(self, ip):
        """Start OpenVas scan on the ip provided.

        Args:
            ip: Target ip to scan.
        """
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            target_id = self._create_target(gmp, ip, ALL_IANA_ASSIGNED_TCP_UDP)
            task_id = self._create_task(gmp, ip, target_id, GVMD_FULL_FAST_CONFIG, OPENVAS_SCANNER_ID,)
            report_id = self._start_task(gmp, task_id)
            logger.info('Started scan of host %s. Corresponding report ID is %s', str(ip), str(report_id))

    def _create_target(self, gmp, ip, port_list_id):
        """Create gmp target https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_create_target.

        Args:
            gmp: GMP object.
            ip: Target ip to scan.
            port_list_id: ports to scan

        Returns:
            - target id.
        """
        name = f'Testing Host {ip} {datetime.datetime.now()}'
        response = gmp.create_target(name=name, hosts=[ip], port_list_id=port_list_id)
        return response.get('id')

    def _create_task(self, gmp, ip, target_id, scan_config_id, scanner_id):
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_create_task.

        Args:
            gmp: GMP object.
            ip: Target ip to scan.
            port_list_id: ports to scan

        Returns:
            - target id.
        """
        name = f'Scan Host {ip_address}'
        response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id,)
        return response.get('id')

    def _start_task(self, gmp, task_id):
        response = gmp.start_task(task_id)
        return response[0].text
