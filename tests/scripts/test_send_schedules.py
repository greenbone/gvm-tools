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
from unittest.mock import patch
from pathlib import Path
from argparse import Namespace
from lxml import etree
from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class SendSchedulesTestCase(unittest.TestCase):
    def setUp(self):
        self.send_schedules = load_script(
            (CWD.parent.parent / 'scripts'), 'send-schedules'
        )

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_sent_schedule(self, mock_gmp: GmpMockFactory):
        schedule_xml_path = CWD / 'example_schedules.xml'
        schedule_xml_str = schedule_xml_path.read_text()

        mock_gmp.mock_responses(
            'create_schedule',
            [
                '<create_schedule_response status="201" status_text="OK,'
                'resource created" id="75be149a-0877-40f9-97c0-dfea31311e35"/>',
                '<create_schedule_response status="201" status_text="OK,'
                'resource created" id="42da6616-f32d-47b4-8d6b-2e4553c42ee7"/>',
            ],
        )

        schedule = etree.XML(schedule_xml_str)

        self.send_schedules.parse_send_xml_tree(mock_gmp.gmp_protocol, schedule)

    @patch('gvm.protocols.latest.Gmp', new_callable=GmpMockFactory)
    def test_args(self, mock_gmp: GmpMockFactory):
        args = Namespace(script=['foo'])
        with self.assertRaises(SystemExit):
            self.send_schedules.check_args(gmp=mock_gmp, args=args)

        args2 = Namespace(script=['foo', 'bar', 'baz'])

        with self.assertRaises(SystemExit):
            self.send_schedules.check_args(gmp=mock_gmp, args=args2)
