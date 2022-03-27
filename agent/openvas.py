"""Wrapper for OpenVas scanner to start the scan and extract the results."""
import datetime
import logging
import base64
import socket
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
    def start_scan(self, target: str) -> str:
        """Start OpenVas scan on the ip provided.

        Args:
            target: Target ip to scan.
        Returns:
            OpenVas task identifier.
        """
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            logger.debug('Creating target')
            target_id = self._create_target(gmp, target, ALL_IANA_ASSIGNED_TCP_UDP)
            logger.debug('Creating task for target %s', target_id)
            task_id = self._create_task(gmp, target, target_id, GVMD_FULL_FAST_CONFIG, OPENVAS_SCANNER_ID, )
            logger.debug('Creating report for task %s', task_id)
            report_id = self._start_task(gmp, task_id)
            logger.info('Started scan of host %s. Corresponding report ID is %s', str(target), str(report_id))
            return task_id

    def _create_target(self, gmp: openvas_gmp.Gmp, target: str, port_list_id: str) -> str:
        """Create gmp target https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_create_target.

        Args:
            gmp: GMP object.
            target: Target ip to scan.
            port_list_id: ports to scan

        Returns:
            OpenVas target identifier.
        """
        name = f'Testing Host {target} {datetime.datetime.now()}'
        response = gmp.create_target(name=name, hosts=[target], port_list_id=port_list_id)
        return response.get('id')

    def _create_task(self, gmp: openvas_gmp.Gmp, ip: str, target_id: str, scan_config_id: str, scanner_id: str) -> str:
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_create_task.

        Args:
            gmp: GMP object.
            ip: Target ip to scan.
            target_id: Ids of hosts targeted by the scan.
            scan_config_id: scan configuration used by the task
            scanner_id: scanner to use for scanning the target.

        Returns:
            - OpenVas task identifier.
        """
        name = f'Scan Host {ip}'
        response = gmp.create_task(name=name, config_id=scan_config_id, target_id=target_id, scanner_id=scanner_id,)
        return response.get('id')

    def _start_task(self, gmp: openvas_gmp.Gmp, task_id: str) -> str:
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_start_task.

        Args:
            gmp: GMP object.
            task_id: task id.

        Returns:
            - task result.
        """
        response = gmp.start_task(task_id)
        return response[0].text

    def wait_task(self, task_id: str) -> bool:
        """check gmp task status and wait until it is Done.

        Args:
            task_id: task id.

        Returns:
            - bool task status.
        """
        logger.info('Waiting for task %s', task_id)
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            while True:
                try:
                    resp_tasks = gmp.get_tasks().xpath('task')
                    for task in resp_tasks:
                        logger.debug('Checking task %s', task.xpath('@id')[0])
                        if task.xpath('@id')[0] == task_id:
                            logger.info('Scan progress %s', str(task.find('progress').text))
                            if task.find('status').text == 'Done':
                                return True
                except socket.timeout:
                    logger.error('Socket timeout error')
                time.sleep(WAIT_TIME)

    def get_results(self) -> str:
        """get gmp report result in csv format.

        Returns:
            - str csv results.
        """
        connection = gvm.connections.TLSConnection(hostname='localhost')
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            report_format_id = ''
            report_formats = gmp.get_report_formats()
            for report_format in report_formats:
                for rf in report_format:
                    if rf.text == 'CSV result list.':
                        report_format_id = report_format.attrib.get('id')

            result_reports = []
            all_reports = gmp.get_reports()
            for report in all_reports:
                if report.tag == 'report':
                    for one_report in report:
                        if one_report.tag == 'report':
                            result_reports.append(report.attrib.get('id'))

            # Get out the reports and get them as csv files to use
            for report_id in result_reports:
                response = gmp.get_report(report_id, report_format_id=report_format_id,ignore_pagination=True,
                                          details=True)
                report_element = response.find('report')
                content = report_element.find('report_format').tail
                data = str(base64.b64decode(content), 'utf-8')
                return data
