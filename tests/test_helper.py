# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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
import sys
import unittest
from unittest import mock

from gvm.errors import GvmError

from gvmtools.helper import Table, do_not_run_as_root, authenticate, run_script


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


class DoNotRunAsRootTestCase(unittest.TestCase):
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


class AuthenticateFunctionTestCase(unittest.TestCase):
    def test_authenticate_already_authenticated(self):
        mock_gmp = self.create_gmp_mock(True)

        self.assertIsNone(authenticate(mock_gmp))

    @mock.patch('gvmtools.helper.input', return_value='foo')
    def test_authenticate_username_is_none(
        self, mock_input
    ):  # pylint: disable=unused-argument,line-too-long
        mock_gmp = self.create_gmp_mock(False)

        return_value = authenticate(mock_gmp, password='bar')

        self.assertTrue(isinstance(return_value, tuple))
        self.assertEqual(return_value[0], 'foo')
        self.assertEqual(return_value[1], 'bar')

    @mock.patch('gvmtools.helper.getpass')
    def test_authenticate_password_is_none(self, mock_getpass):
        mock_gmp = self.create_gmp_mock(False)
        mock_getpass.getpass = mock.MagicMock(return_value='SuperSecret123!')

        return_value = authenticate(mock_gmp, username='user')

        self.assertTrue(isinstance(return_value, tuple))
        self.assertEqual(return_value[0], 'user')
        self.assertEqual(return_value[1], 'SuperSecret123!')

    def test_authenticate(self):
        mock_gmp = self.create_gmp_mock(False)

        return_value = authenticate(
            mock_gmp, username='user', password='password'
        )

        self.assertTrue(isinstance(return_value, tuple))
        self.assertEqual(return_value[0], 'user')
        self.assertEqual(return_value[1], 'password')

    def test_authenticate_bad_credentials(self):
        mock_gmp = self.create_gmp_mock(False)

        def my_authenticate(username, password):
            raise GvmError('foo')

        mock_gmp.authenticate = my_authenticate

        self.assertRaises(GvmError, authenticate, mock_gmp, 'user', 'password')

    def create_gmp_mock(self, authenticated_return_value):
        mock_gmp = mock.MagicMock()
        mock_gmp.is_authenticated = mock.MagicMock(
            return_value=authenticated_return_value
        )
        return mock_gmp


class RunScriptTestCase(unittest.TestCase):
    @mock.patch('gvmtools.helper.open')
    @mock.patch('gvmtools.helper.exec')
    def test_run_script(self, mock_exec, mock_open):
        path = 'foo'
        global_vars = ['OpenVAS', 'is', 'awesome']
        mock_open().read.return_value = 'file content'

        run_script(path, global_vars)

        mock_open.assert_called_with(path, 'r', newline='')
        mock_exec.assert_called_with('file content', global_vars)

    @mock.patch('gvmtools.helper.open')
    @mock.patch('gvmtools.helper.print')
    def test_run_script_file_not_found(self, mock_print, mock_open):
        def my_open(path, mode, newline):
            raise FileNotFoundError

        mock_open.side_effect = my_open

        path = 'foo'
        global_vars = ['OpenVAS', 'is', 'awesome']

        with self.assertRaises(SystemExit):
            run_script(path, global_vars)

        mock_print.assert_called_with(
            'Script {path} does not exist'.format(path=path), file=sys.stderr
        )
