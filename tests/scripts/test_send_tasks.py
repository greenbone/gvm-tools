# -*- coding: utf-8 -*-
# Copyright (C) 2020-2021 Greenbone Networks GmbH
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
# along with this program.  If not, see<http://www.gnu.org/licenses/>


import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from lxml import etree
from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class SendTasksTestCase(unittest.TestCase):
    def setUp(self):
        self.send_tasks = load_script(
            (CWD.parent.parent / 'scripts'), 'send-tasks'
        )

    @patch('builtins.input', lambda *args: 'y')
    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_sent_task(self, mock_gmp: GmpMockFactory):
        task_xml_path = CWD / 'example_task.xml'
        task_xml_str = task_xml_path.read_text()

        self.send_tasks.numerical_option = MagicMock(return_value=1)

        configs_file = CWD / 'get_scan_configs.xml'
        configs = configs_file.read_text()
        mock_gmp.mock_response('get_scan_configs', configs)

        mock_gmp.mock_response(
            'get_scanners',
            '<get_scanners_response status="200" status_text="OK">'
            '<scanner id="c1c85af7-0cca-4690-8ccc-c79feb5588cf">'
            '<name>as</name>'
            '</scanner>'
            '<scanner id="6acd0832-df90-11e4-b9d5-28d24461215b">'
            '<name>CVE</name>'
            '</scanner>'
            '<scanner id="08b69003-5fc2-4037-a479-93b440211c73">'
            '<name>OpenVAS Default</name>'
            '</scanner>'
            '</get_scanners_response>',
        )

        mock_gmp.mock_response(
            'get_targets',
            '<get_targets_response status="200" status_text="OK">'
            '<target id="60f95d0e-029e-4931-a13a-b1d11260517d">'
            '<name>own</name>'
            '</target>'
            '<target id="ead9576c-5a4d-4081-b98d-ccd77d5d16f8">'
            '<name>Target for xn</name>'
            '</target>'
            '<target id="6c9f73f5-f14c-42bf-ab44-edb8d2493dbc">'
            '<name>Unnamed</name>'
            '</target>'
            '<target id="a1f478c1-27d0-4d8c-959f-150625186421">'
            '<name>work</name>'
            '</target>'
            '<target id="5ca97fe1-694d-4e4a-bd4c-55529719d17e">'
            '<name>work2</name>'
            '</target>'
            '</get_targets_response>',
        )

        mock_gmp.mock_response(
            'create_task',
            '<create_task_response status="201" status_text="OK,'
            'resource created" id="c8ef0597-e2c1-4e23-869f-072fa2914bf2"/>',
        )

        task = etree.XML(task_xml_str)

        tasks = self.send_tasks.parse_send_xml_tree(mock_gmp.gmp_protocol, task)
        self.assertEqual(tasks, ['c8ef0597-e2c1-4e23-869f-072fa2914bf2'])
