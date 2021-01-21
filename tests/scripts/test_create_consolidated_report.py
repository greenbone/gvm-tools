# -*- coding: utf-8 -*-
# Copyright (C) 2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import unittest
from datetime import date

from unittest.mock import patch
from pathlib import Path
from lxml import etree
from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class CreateConsolidatedReportsTestCase(unittest.TestCase):
    def setUp(self):
        self.create_consolidated_report = load_script(
            (CWD.parent.parent / 'scripts'), 'create-consolidated-report'
        )

    def test_parse_period(self):
        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["a/b/c", "2020/02/03"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["1/2/3/4", "2020/02/03"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/02/03", "a/b/c"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/02/03", "1/2/3/4"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/20/03", "2001/2/3"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/12/03", "2001/2/300"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/12/03", "2001/22/30"]
            )

        with self.assertRaises(SystemExit), self.assertRaises(ValueError):
            self.create_consolidated_report.parse_period(
                ["2020/12/43", "2001/2/3"]
            )

        date1, date2 = self.create_consolidated_report.parse_period(
            ["1980/1/11", "2001/2/3"]
        )
        self.assertEqual(date1, date(1980, 1, 11))
        self.assertEqual(date2, date(2001, 2, 3))

    def test_parse_tags(self):
        tags = ['abc', 'dba8624e-a56c-4901-a3f2-591f062e4c20']

        filter_tags = self.create_consolidated_report.parse_tags(tags)

        self.assertEqual(filter_tags[0], 'tag="abc"')
        self.assertEqual(
            filter_tags[1], 'tag_id="dba8624e-a56c-4901-a3f2-591f062e4c20"'
        )

    def test_generate_task_filter(self):
        asserted_task_filter = (
            'rows=-1 last>2020-01-01 and last<2020-02-01 and tag="blah"'
        )
        period_start = date(2020, 1, 1)
        period_end = date(2020, 2, 1)
        tags = ['tag="blah"']

        task_filter = self.create_consolidated_report.generate_task_filter(
            period_start, period_end, tags
        )

        self.assertEqual(task_filter, asserted_task_filter)

        asserted_task_filter = (
            'rows=-1 last>2020-01-01 and last<2020-02-01 and '
            'tag="blah" or last>2020-01-01 and last<2020-02-01'
            ' and tag="blah2"'
        )
        tags = ['tag="blah"', 'tag="blah2"']

        task_filter = self.create_consolidated_report.generate_task_filter(
            period_start, period_end, tags
        )

        self.assertEqual(task_filter, asserted_task_filter)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_get_last_reports_from_tasks(self, mock_gmp: GmpMockFactory):
        mock_gmp.mock_response(
            'get_tasks',
            '<get_tasks_response status="200" status_text="OK">'
            '  <apply_overrides>0</apply_overrides>'
            '  <task id="ef4469db-1cd7-4859-ba5f-45f72f49f09e">'
            '    <last_report>'
            '      <report id="4108fe11-91c8-4b7b-90da-854e3200af19">'
            '      </report>'
            '    </last_report>'
            '  </task>'
            '  <task id="bdd80dd6-9c7b-47b9-a87b-e2ca28fae2df">'
            '    <last_report>'
            '      <report id="55af942a-fa45-472c-aa50-f2af77d700a0">'
            '      </report>'
            '    </last_report>'
            '  </task>'
            '  <task id="6e5373cd-e69a-4008-afc3-a6d05e22507f">'
            '    <last_report>'
            '      <report id="52b67045-2c2c-4dbd-af58-ecf814d92f07">'
            '      </report>'
            '    </last_report>'
            '  </task>'
            '  <task id="bab515c2-156b-451f-9f1c-7af5b2c4b568">'
            '    <last_report>'
            '      <report id="52b67045-2c2c-4dbd-af58-ecf814d92f07">'
            '      </report>'
            '    </last_report>'
            '  </task>'
            '</get_tasks_response>',
        )

        reports = self.create_consolidated_report.get_last_reports_from_tasks(
            mock_gmp.gmp_protocol,
            task_filter=(
                'rows=-1 last>2020-01-01 and ' 'last<2020-02-01 and tag="blah"'
            ),
        )

        asserted_reports = [
            '4108fe11-91c8-4b7b-90da-854e3200af19',
            '55af942a-fa45-472c-aa50-f2af77d700a0',
            '52b67045-2c2c-4dbd-af58-ecf814d92f07',
        ]
        self.assertEqual(reports, asserted_reports)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_combine_reports_with_term(self, mock_gmp: GmpMockFactory):
        reports = [
            '00000000-0000-0000-0000-000000000000',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000002',
        ]

        mock_gmp.mock_responses(
            'get_report',
            [
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000000">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0001-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000000">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<ports max="-1" start="1">'
                '<port>0<host>127.0.0.0</host></port>'
                '<port>1<host>127.0.0.1</host></port></ports>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000000">'
                '</result>'
                '<result id="00000001-0000-0000-0000-000000000001">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '</report></report></get_reports_response>',
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000001">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0002-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000001">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<ports max="-1" start="1">'
                '<port>2<host>127.0.0.2</host></port>'
                '<port>3<host>127.0.0.3</host></port></ports>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000002"></result>'
                '<result id="00000001-0000-0000-0000-000000000003">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '<host><ip>127.0.0.0</ip></host></report>'
                '</report></get_reports_response>',
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000002">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0003-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000002">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000004">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '<host><ip>127.0.0.1</ip></host></report>'
                '</report></get_reports_response>',
            ],
        )

        combined_report = self.create_consolidated_report.combine_reports(
            mock_gmp.gmp_protocol, reports, filter_term="foo", filter_id=None
        )

        ports = combined_report.find('report').find('ports').findall('port')
        i = 0
        for port in ports:
            self.assertEqual(port.text, f'{str(i)}')
            i += 1

        self.assertEqual(i, 4)

        results = (
            combined_report.find('report').find('results').findall('result')
        )
        i = 0
        for result in results:
            self.assertEqual(
                result.get('id'), f'00000001-0000-0000-0000-00000000000{str(i)}'
            )
            i += 1

        self.assertEqual(i, 5)

        hosts = combined_report.find('report').findall('host')

        i = 0
        for host in hosts:
            self.assertEqual(host.find('ip').text, f'127.0.0.{str(i)}')
            i += 1

        self.assertEqual(i, 2)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_combine_reports_with_id(self, mock_gmp: GmpMockFactory):
        reports = [
            '00000000-0000-0000-0000-000000000000',
            '00000000-0000-0000-0000-000000000001',
            '00000000-0000-0000-0000-000000000002',
        ]

        mock_gmp.mock_responses(
            'get_report',
            [
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000000">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0001-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000000">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<ports max="-1" start="1">'
                '<port>0<host>127.0.0.0</host></port>'
                '<port>1<host>127.0.0.1</host></port></ports>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000000">'
                '</result>'
                '<result id="00000001-0000-0000-0000-000000000001">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '</report></report></get_reports_response>',
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000001">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0002-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000001">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<ports max="-1" start="1">'
                '<port>2<host>127.0.0.2</host></port>'
                '<port>3<host>127.0.0.3</host></port></ports>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000002"></result>'
                '<result id="00000001-0000-0000-0000-000000000003">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '<host><ip>127.0.0.0</ip></host></report>'
                '</report></get_reports_response>',
                '<get_reports_response status="200" status_text="OK">'
                '<report id="00000000-0000-0000-0000-000000000002">'
                '<name>2020-11-13T14:47:28Z</name>'
                '<creation_time>2020-11-13T14:47:28Z</creation_time>'
                '<modification_time>2020-11-13T14:47:28Z</modification_time>'
                '<task id="00000000-0000-0000-0003-000000000000">'
                '<name>Offline Scan from 2020-11-13T15:47:28+01:00 8</name>'
                '</task>'
                '<report id="00000000-0000-0000-0000-000000000002">'
                '<scan_run_status>Done</scan_run_status>'
                '<timestamp>2020-11-13T14:47:48Z</timestamp>'
                '<scan_start>2020-11-13T14:47:28Z</scan_start>'
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000004">'
                '</result></results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '<host><ip>127.0.0.1</ip></host></report>'
                '</report></get_reports_response>',
            ],
        )

        combined_report = self.create_consolidated_report.combine_reports(
            mock_gmp.gmp_protocol, reports, filter_term="", filter_id='123'
        )

        ports = combined_report.find('report').find('ports').findall('port')
        i = 0
        for port in ports:
            self.assertEqual(port.text, f'{str(i)}')
            i += 1

        self.assertEqual(i, 4)

        results = (
            combined_report.find('report').find('results').findall('result')
        )
        i = 0
        for result in results:
            self.assertEqual(
                result.get('id'), f'00000001-0000-0000-0000-00000000000{str(i)}'
            )
            i += 1

        self.assertEqual(i, 5)

        hosts = combined_report.find('report').findall('host')

        i = 0
        for host in hosts:
            self.assertEqual(host.find('ip').text, f'127.0.0.{str(i)}')
            i += 1

        self.assertEqual(i, 2)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_send_report(self, mock_gmp: GmpMockFactory):

        combined_report = etree.fromstring(
            '<report id="20574712-c404-4a04-9c83-03144ae02dca" '
            'format_id="d5da9f67-8551-4e51-807b-b6a873d70e34" '
            'extension="xml" content_type="text/xml">'
            '<report id="20574712-c404-4a04-9c83-03144ae02dca">'
            '<results start="1" max="-1">'
            '<result id="00000001-0000-0000-0000-000000000000"/>'
            '<result id="00000001-0000-0000-0000-000000000001"/>'
            '<result id="00000001-0000-0000-0000-000000000002"/>'
            '<result id="00000001-0000-0000-0000-000000000003"/>'
            '<result id="00000001-0000-0000-0000-000000000004"/>'
            '</results></report></report>'
        )

        report_id = '0e4d8fb2-47fa-494e-a242-d5327d3772f9'

        mock_gmp.mock_response(
            'import_report',
            '<create_report_response status="201" status_text="OK, '
            f'resource created" id="{report_id}"/>',
        )

        mock_gmp.mock_response(
            'create_container_task',
            '<create_task_response status="201" status_text="OK, '
            'resource created" id="6488ef71-e2d5-491f-95bd-ed9f915fa179"/>',
        )

        period_start = date(2020, 1, 1)
        period_end = date(2020, 2, 1)

        created_report_id = self.create_consolidated_report.send_report(
            gmp=mock_gmp.gmp_protocol,
            combined_report=combined_report,
            period_start=period_start,
            period_end=period_end,
        )

        self.assertEqual(report_id, created_report_id)
