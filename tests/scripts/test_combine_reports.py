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
from unittest.mock import patch
from pathlib import Path
from argparse import Namespace
from lxml import etree
from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class CombineReportsTestCase(unittest.TestCase):
    def setUp(self):
        self.combine_reports = load_script(
            (CWD.parent.parent / 'scripts'), 'combine-reports'
        )

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_combine_reports(self, mock_gmp: GmpMockFactory):
        # bah!
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
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000000">'
                '</result>'
                '<result id="00000001-0000-0000-0000-000000000001">'
                '</result>'
                '</results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '</report>'
                '</report>'
                '</get_reports_response>',
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
                '<results start="1" max="100">'
                '<result id="00000001-0000-0000-0000-000000000002">'
                '</result>'
                '<result id="00000001-0000-0000-0000-000000000003">'
                '</result>'
                '</results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '</report>'
                '</report>'
                '</get_reports_response>',
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
                '</result>'
                '</results>'
                '<scan_end>2020-11-13T14:47:28Z</scan_end>'
                '</report>'
                '</report>'
                '</get_reports_response>',
            ],
        )
        args = Namespace(
            script=[
                'foo',
                '00000000-0000-0000-0000-000000000000',
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
            ]
        )

        combined_report = self.combine_reports.combine_reports(
            gmp=mock_gmp.gmp_protocol, args=args
        )

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

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_send_report(self, mock_gmp: GmpMockFactory):

        args = Namespace(
            script=[
                'foo',
                '00000000-0000-0000-0000-000000000000',
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
            ]
        )

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

        created_report_id = self.combine_reports.send_report(
            gmp=mock_gmp.gmp_protocol,
            args=args,
            combined_report=combined_report,
        )

        self.assertEqual(report_id, created_report_id)
