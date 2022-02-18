"""Wrapper for OpenVas scanner to start the scan and extract the results."""
import base64
import datetime
import logging
import time

import gvm
from gvm import transforms
from gvm.protocols import gmp as openvas_gmp

logger = logging.getLogger(__name__)

ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
GVMD_FULL_FAST_CONFIG = 'daba56c8-73ec-11df-a475-002264764cea'
OPENVAS_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
GMP_USERNAME = 'admin'
GMP_PASSWORD = 'admin'
GMP_HOST = 'localhost'
WAIT_TIME = 30


class OpenVas:
    """OpenVas wrapper to enable using openvas scanner from ostorlab agent class."""

    def __init__(self, host: str = GMP_HOST, username: str = GMP_USERNAME, password: str = GMP_PASSWORD) -> None:
        super().__init__()
        self._host = host
        self._username = username
        self._password = password

    def start_scan(self, ip):
        """Start OpenVas scan on the ip provided.

        Args:
            ip: Target ip to scan.
        """
        connection = gvm.connections.TLSConnection(hostname=self._host)
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            target_id = self._create_target(gmp, ip, ALL_IANA_ASSIGNED_TCP_UDP)
            task_id = self._create_task(gmp, ip, target_id, GVMD_FULL_FAST_CONFIG, OPENVAS_SCANNER_ID, )
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
            target_id: hosts scanned by the task.
            scan_config_id: scan configuration used by the task
            scanner_id: scanner to use for scanning the target.

        Returns:
            - task id.
        """
        name = f'Scan Host {ip}'
        response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id, )
        return response.get('id')

    def _start_task(self, gmp, task_id):
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_start_task.

        Args:
            gmp: GMP object.
            task_id: task id.

        Returns:
            - task result.
        """
        response = gmp.start_task(task_id)
        return response[0].text

    def wait_scan(self, scan_id: str) -> None:
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            response = gmp.get_tasks(task_id=scan_id)
            while response.task.status != 'DONE':
                time.sleep(WAIT_TIME)
                logger.info('Scan progress %s', str(response.task.progress))

    def get_results(self, scan_id: str):
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            # Get the CSV report type
            report_format_id = ""
            report_format = gmp.get_report_formats()
            for report in report_format:
                for format in report:
                    if format.text == 'CSV result list.':
                        report_format_id = report.attrib.get('id')

            result_reports = []
            all_reports = gmp.get_reports()
            for report in all_reports:
                if report.tag == 'report':
                    for one_report in report:
                        if one_report.tag == 'report':
                            result_reports.append(report.attrib.get('id'))

            # Get out the reports and get them as csv files to use
            for report_id in result_reports:
                reportscv = gmp.get_report(report_id, report_format_id=report_format_id,
                                           filter="apply_overrides=0 min_qod=70",
                                           ignore_pagination=True, details=True)
                # pretty_print(reportscv)
                result_id = reportscv.get_reports_response.report['id']
                base64CVSData = reportscv.get_reports_response.report.cdata
                data = str(base64.b64decode(base64CVSData), "utf-8")
                print(data)
                return data
