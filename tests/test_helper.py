# -*- coding: utf-8 -*-
# Copyright (C) 2019 Greenbone Networks GmbH
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
from unittest import mock

from gvmtools.helper import Table, do_not_run_as_root


class TableTestCase(unittest.TestCase):
    def setUp(self):
        self.heading = ['ID', 'Name', 'Severity']
        self.rows = [
            ['1', 'foobar', 'high'],
            ['2', 'bla', 'low'],
            ['3', 'blub', 'medium'],
        ]
        self.divider = ' - '

        self.table = Table(
            heading=self.heading, rows=self.rows, divider=self.divider
        )

    def test_init_no_args(self):
        table = Table()

        self.assertListEqual(table.heading, [])
        self.assertListEqual(table.rows, [])
        self.assertEqual(table.divider, ' | ')

    def test_init_with_args(self):
        self.assertListEqual(self.table.heading, self.heading)
        self.assertListEqual(self.table.rows, self.rows)
        self.assertEqual(self.table.divider, self.divider)

    def test_calculate_dimensions(self):
        expected_result = [
            len(self.heading[0]),
            len(self.rows[0][1]),
            len(self.heading[2]),
        ]

        column_sizes = (
            self.table._calculate_dimensions()  # pylint: disable=protected-access
        )

        self.assertEqual(column_sizes, expected_result)

    def test_create_column(self):
        column = 'foobar'
        size = 20
        expected = 'foobar              '

        result = self.table._create_column(  # pylint: disable=protected-access
            column, size
        )

        self.assertEqual(result, expected)

    def test_create_row(self):
        columns = ['foo', 'bar', 'blub']
        expected = self.divider.join(columns)

        result = self.table._create_row(columns)  # pylint: disable=W0212

        self.assertEqual(result, expected)

    def test_str(self):
        expected = (
            'ID - Name   - Severity\n'
            + '-- - ------ - --------\n'
            + '1  - foobar - high    \n'
            + '2  - bla    - low     \n'
            + '3  - blub   - medium  '
        )

        self.assertEqual(str(self.table), expected)


class HelperFunctionsTestCase(unittest.TestCase):
    @mock.patch('gvmtools.helper.os')
    def test_do_not_run_as_root_as_root(self, mock_os):
        mock_os.geteuid = unittest.mock.MagicMock(spec='geteuid')
        mock_os.geteuid.return_value = 0

        self.assertRaises(RuntimeError, do_not_run_as_root)

    @mock.patch('gvmtools.helper.os')
    def test_do_not_run_as_root_as_non_root(self, mock_os):
        mock_os.geteuid = unittest.mock.MagicMock(spec='geteuid')
        mock_os.geteuid.return_value = 123

        self.assertIsNone(do_not_run_as_root())
