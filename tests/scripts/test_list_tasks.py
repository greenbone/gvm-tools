# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2024 Greenbone AG
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
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from gvmtools.helper import Table

from . import GmpMockFactory, load_script

CWD = Path(__file__).absolute().parent


class ListTasksTestCase(unittest.TestCase):
    def setUp(self):
        self.list_tasks = load_script(
            (CWD.parent.parent / "scripts"), "list-tasks"
        )

    @patch("gvm.protocols.latest.Gmp", new_callable=GmpMockFactory)
    @patch("builtins.print")
    def test_duration_with_timezone_offset(
        self, mock_print, mock_gmp: GmpMockFactory
    ):
        args = Namespace(script=["foo"])

        mock_gmp.mock_response(
            "get_tasks",
            '<get_tasks_response status="200" status_text="OK">'
            '<task id="7f32c1f4-c5c8-4035-b4fb-5b1e220bc052">'
            "<name>Test</name>"
            "<average_duration>4115</average_duration>"
            "<last_report>"
            '<report id="cbf8c159-d3f8-4adf-b17d-fd53abf20e52">'
            "<scan_start>2024-03-12T16:35:01-07:00</scan_start>"
            "<scan_end>2024-03-12T17:43:36-07:00</scan_end>"
            "</report>"
            "</last_report>"
            "</task>"
            "</get_tasks_response>",
        )
        self.list_tasks.list_tasks(mock_gmp.gmp_protocol, args)

        table = mock_print.call_args[0][0]
        self.assertIsInstance(table, Table)
        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][1], "Test")
        self.assertEqual(table.rows[0][7], "1.14")
        self.assertEqual(table.rows[0][8], "1.14")

    @patch("gvm.protocols.latest.Gmp", new_callable=GmpMockFactory)
    @patch("builtins.print")
    def test_duration_in_UTC(self, mock_print, mock_gmp: GmpMockFactory):
        args = Namespace(script=["foo"])

        mock_gmp.mock_response(
            "get_tasks",
            '<get_tasks_response status="200" status_text="OK">'
            '<task id="7f32c1f4-c5c8-4035-b4fb-5b1e220bc052">'
            "<name>Test</name>"
            "<average_duration>14444</average_duration>"
            "<last_report>"
            '<report id="cbf8c159-d3f8-4adf-b17d-fd53abf20e52">'
            "<scan_start>2024-09-27T14:30:01Z</scan_start>"
            "<scan_end>2024-09-27T18:30:45Z</scan_end>"
            "</report>"
            "</last_report>"
            "</task>"
            "</get_tasks_response>",
        )
        self.list_tasks.list_tasks(mock_gmp.gmp_protocol, args)

        table = mock_print.call_args[0][0]
        self.assertIsInstance(table, Table)
        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][1], "Test")
        self.assertEqual(table.rows[0][7], "4.01")
        self.assertEqual(table.rows[0][8], "4.01")

    @patch("gvm.protocols.latest.Gmp", new_callable=GmpMockFactory)
    @patch("builtins.print")
    def test_missing_last_report(self, mock_print, mock_gmp: GmpMockFactory):
        args = Namespace(script=["foo"])

        mock_gmp.mock_response(
            "get_tasks",
            '<get_tasks_response status="200" status_text="OK">'
            '<task id="7f32c1f4-c5c8-4035-b4fb-5b1e220bc052">'
            "<name>Test</name>"
            "<average_duration>0</average_duration>"
            "</task>"
            "</get_tasks_response>",
        )
        self.list_tasks.list_tasks(mock_gmp.gmp_protocol, args)

        table = mock_print.call_args[0][0]
        self.assertIsInstance(table, Table)
        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][1], "Test")
        self.assertEqual(table.rows[0][7], "0.00")
        self.assertEqual(table.rows[0][8], "")
