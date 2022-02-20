"""Wrapper for OpenVas scanner to start the scan and extract the results."""
import datetime
import logging
import base64
import csv, json
import time

import gvm
from gvm.protocols import gmp as openvas_gmp
from gvm import transforms

logger = logging.getLogger(__name__)

ALL_IANA_ASSIGNED_TCP_UDP = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
GVMD_FULL_FAST_CONFIG = 'daba56c8-73ec-11df-a475-002264764cea'
OPENVAS_SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
GMP_USERNAME = 'admin'
GMP_PASSWORD = 'admin'
WAIT_TIME = 30

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
            target_id: hosts scanned by the task.
            scan_config_id: scan configuration used by the task
            scanner_id: scanner to use for scanning the target.

        Returns:
            - task id.
        """
        name = f'Scan Host {ip}'
        response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id,)
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

    def wait_task(self, task_id):
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            while True:
                resp_tasks = gmp.get_tasks().xpath('task')
                for task in resp_tasks:
                    if task.xpath('@id')[0] == task_id:
                        if task.find('status').text == 'Done':
                            return True
                        else:
                            logger.info('Scan progress %s', str(task.find('status').text))
                time.sleep(WAIT_TIME)

    def get_results(self):
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
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
                response = gmp.get_report(report_id, report_format_id=report_format_id,
                                           filter="apply_overrides=0 min_qod=70",
                                           ignore_pagination=True, details=True)
                report_element = response.find("report")
                content = report_element.find("report_format").tail
                data = str(base64.b64decode(content), "utf-8")
                return data
