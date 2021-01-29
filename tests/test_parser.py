# -*- coding: utf-8 -*-
# Copyright (C) 2019-2021 Greenbone Networks GmbH
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

import os
import sys
import unittest

from unittest.mock import patch
from pathlib import Path

from argparse import Namespace
from gvm.connections import (
    DEFAULT_UNIX_SOCKET_PATH,
    DEFAULT_TIMEOUT,
    UnixSocketConnection,
    TLSConnection,
    SSHConnection,
)

from gvmtools.parser import CliParser, create_parser, create_connection

from . import SuppressOutput

__here__ = Path(__file__).parent.resolve()


class ConfigParserTestCase(unittest.TestCase):
    def setUp(self):
        self.test_config_path = __here__ / 'test.cfg'

        self.assertTrue(self.test_config_path.is_file())

        self.parser = CliParser('TestParser', 'test.log')

    def test_socket_defaults_from_config(self):
        args = self.parser.parse_args(
            ['--config', str(self.test_config_path), 'socket']
        )

        self.assertEqual(args.foo, 'bar')
        self.assertEqual(args.timeout, 1000)
        self.assertEqual(args.gmp_password, 'bar')
        self.assertEqual(args.gmp_username, 'bar')
        self.assertEqual(args.socketpath, '/foo/bar.sock')

    def test_ssh_defaults_from_config(self):
        args = self.parser.parse_args(
            ['--config', str(self.test_config_path), 'ssh', '--hostname', 'foo']
        )

        self.assertEqual(args.foo, 'bar')
        self.assertEqual(args.timeout, 1000)
        self.assertEqual(args.gmp_password, 'bar')
        self.assertEqual(args.gmp_username, 'bar')
        self.assertEqual(args.ssh_password, 'lorem')
        self.assertEqual(args.ssh_username, 'ipsum')
        self.assertEqual(args.port, 123)

    def test_tls_defaults_from_config(self):
        args = self.parser.parse_args(
            ['--config', str(self.test_config_path), 'tls', '--hostname', 'foo']
        )

        self.assertEqual(args.foo, 'bar')
        self.assertEqual(args.timeout, 1000)
        self.assertEqual(args.gmp_password, 'bar')
        self.assertEqual(args.gmp_username, 'bar')
        self.assertEqual(args.certfile, 'foo.cert')
        self.assertEqual(args.keyfile, 'foo.key')
        self.assertEqual(args.cafile, 'foo.ca')
        self.assertEqual(args.port, 123)

    @patch('gvmtools.parser.logger')
    @patch('gvmtools.parser.Path')
    def test_resolve_file_not_found_error(self, path_mock, logger_mock):
        # Making sure that resolve raises an error
        def resolve_raises_error():
            raise FileNotFoundError()

        configpath = unittest.mock.MagicMock()
        configpath.expanduser().resolve = unittest.mock.MagicMock(
            side_effect=resolve_raises_error
        )
        path_mock.return_value = configpath

        logger_mock.debug = unittest.mock.MagicMock()

        args = self.parser.parse_args(['socket'])

        self.assertIsInstance(args, Namespace)
        self.assertEqual(args.connection_type, 'socket')
        self.assertEqual(args.config, '~/.config/gvm-tools.conf')
        logger_mock.debug.assert_any_call(
            'Ignoring non existing config file %s', '~/.config/gvm-tools.conf'
        )

    @patch('gvmtools.parser.Path')
    @patch('gvmtools.parser.Config')
    def test_config_load_raises_error(self, config_mock, path_mock):
        def config_load_error():
            raise Exception

        config = unittest.mock.MagicMock()
        config.load = unittest.mock.MagicMock(side_effect=config_load_error)
        config_mock.return_value = config

        # Making sure that the function thinks the config file exists
        configpath_exists = unittest.mock.Mock()
        configpath_exists.expanduser().resolve().exists = (
            unittest.mock.MagicMock(return_value=True)
        )
        path_mock.return_value = configpath_exists

        self.assertRaises(RuntimeError, self.parser.parse_args, ['socket'])


class IgnoreConfigParserTestCase(unittest.TestCase):
    def test_unkown_config_file(self):
        test_config_path = __here__ / 'foo.cfg'

        self.assertFalse(test_config_path.is_file())

        self.parser = CliParser('TestParser', 'test.log')

        args = self.parser.parse_args(
            ['--config', str(test_config_path), 'socket']
        )

        self.assertEqual(args.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(args.gmp_password, '')
        self.assertEqual(args.gmp_username, '')
        self.assertEqual(args.socketpath, DEFAULT_UNIX_SOCKET_PATH)

    def test_unkown_config_file_in_unkown_dir(self):
        test_config_path = __here__ / 'foo' / 'foo.cfg'

        self.assertFalse(test_config_path.is_file())

        self.parser = CliParser('TestParser', 'test.log')

        args = self.parser.parse_args(
            ['--config', str(test_config_path), 'socket']
        )

        self.assertEqual(args.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(args.gmp_password, '')
        self.assertEqual(args.gmp_username, '')
        self.assertEqual(args.socketpath, DEFAULT_UNIX_SOCKET_PATH)


class ParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = CliParser(
            'TestParser', 'test.log', ignore_config=True, prog='gvm-test-cli'
        )


class RootArgumentsParserTest(ParserTestCase):
    def test_config(self):
        args = self.parser.parse_args(['--config', 'foo.cfg', 'socket'])
        self.assertEqual(args.config, 'foo.cfg')

    def test_defaults(self):
        args = self.parser.parse_args(['socket'])
        self.assertEqual(args.config, '~/.config/gvm-tools.conf')
        self.assertEqual(args.gmp_password, '')
        self.assertEqual(args.gmp_username, '')
        self.assertEqual(args.timeout, 60)
        self.assertIsNone(args.loglevel)

    def test_loglevel(self):
        args = self.parser.parse_args(['--log', 'ERROR', 'socket'])
        self.assertEqual(args.loglevel, 'ERROR')

    def test_loglevel_after_subparser(self):
        with SuppressOutput(suppress_stderr=True):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['socket', '--log', 'ERROR'])

    def test_timeout(self):
        args = self.parser.parse_args(['--timeout', '1000', 'socket'])
        self.assertEqual(args.timeout, 1000)

    def test_timeout_after_subparser(self):
        with SuppressOutput(suppress_stderr=True):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['socket', '--timeout', '1000'])

    def test_gmp_username(self):
        args = self.parser.parse_args(['--gmp-username', 'foo', 'socket'])
        self.assertEqual(args.gmp_username, 'foo')

    def test_gmp_username_after_subparser(self):
        with SuppressOutput(suppress_stderr=True):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['socket', '--gmp-username', 'foo'])

    def test_gmp_password(self):
        args = self.parser.parse_args(['--gmp-password', 'foo', 'socket'])
        self.assertEqual(args.gmp_password, 'foo')

    def test_gmp_password_after_subparser(self):
        with SuppressOutput(suppress_stderr=True):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(['socket', '--gmp-password', 'foo'])

    def test_with_unknown_args(self):
        args, script_args = self.parser.parse_known_args(
            ['--gmp-password', 'foo', 'socket', '--bar', '--bar2']
        )
        self.assertEqual(args.gmp_password, 'foo')
        self.assertEqual(script_args, ['--bar', '--bar2'])

    @patch('gvmtools.parser.logging')
    def test_socket_has_no_timeout(self, _logging_mock):
        # pylint: disable=protected-access
        args_mock = unittest.mock.MagicMock()
        args_mock.timeout = -1
        self.parser._parser.parse_known_args = unittest.mock.MagicMock(
            return_value=(args_mock, unittest.mock.MagicMock())
        )

        args, _ = self.parser.parse_known_args(
            ['socket', '--timeout', '--', '-1']
        )

        self.assertIsNone(args.timeout)

    @patch('gvmtools.parser.logging')
    @patch('gvmtools.parser.argparse.ArgumentParser.print_usage')
    @patch('gvmtools.parser.argparse.ArgumentParser._print_message')
    def test_no_args_provided(
        self, _logging_mock, _print_usage_mock, _print_message
    ):
        # pylint: disable=protected-access
        self.parser._set_defaults = unittest.mock.MagicMock()

        self.assertRaises(SystemExit, self.parser.parse_known_args, None)


class SocketParserTestCase(ParserTestCase):
    def test_defaults(self):
        args = self.parser.parse_args(['socket'])
        self.assertEqual(args.socketpath, DEFAULT_UNIX_SOCKET_PATH)

    def test_connection_type(self):
        args = self.parser.parse_args(['socket'])
        self.assertEqual(args.connection_type, 'socket')

    def test_sockpath(self):
        args = self.parser.parse_args(['socket', '--sockpath', 'foo.sock'])
        self.assertEqual(args.socketpath, 'foo.sock')

    def test_socketpath(self):
        args = self.parser.parse_args(['socket', '--socketpath', 'foo.sock'])
        self.assertEqual(args.socketpath, 'foo.sock')


class SshParserTestCase(ParserTestCase):
    def test_defaults(self):
        args = self.parser.parse_args(['ssh', '--hostname=foo'])
        self.assertEqual(args.port, 22)
        self.assertEqual(args.ssh_username, 'gmp')
        self.assertEqual(args.ssh_password, 'gmp')

    def test_connection_type(self):
        args = self.parser.parse_args(['ssh', '--hostname=foo'])
        self.assertEqual(args.connection_type, 'ssh')

    def test_hostname(self):
        args = self.parser.parse_args(['ssh', '--hostname', 'foo'])
        self.assertEqual(args.hostname, 'foo')

    def test_port(self):
        args = self.parser.parse_args(
            ['ssh', '--hostname', 'foo', '--port', '123']
        )
        self.assertEqual(args.port, 123)

    def test_ssh_username(self):
        args = self.parser.parse_args(
            ['ssh', '--hostname', 'foo', '--ssh-username', 'foo']
        )
        self.assertEqual(args.ssh_username, 'foo')

    def test_ssh_password(self):
        args = self.parser.parse_args(
            ['ssh', '--hostname', 'foo', '--ssh-password', 'foo']
        )
        self.assertEqual(args.ssh_password, 'foo')


class TlsParserTestCase(ParserTestCase):
    def test_defaults(self):
        args = self.parser.parse_args(['tls', '--hostname=foo'])
        self.assertIsNone(args.certfile)
        self.assertIsNone(args.keyfile)
        self.assertIsNone(args.cafile)
        self.assertEqual(args.port, 9390)

    def test_connection_type(self):
        args = self.parser.parse_args(['tls', '--hostname=foo'])
        self.assertEqual(args.connection_type, 'tls')

    def test_hostname(self):
        args = self.parser.parse_args(['tls', '--hostname', 'foo'])
        self.assertEqual(args.hostname, 'foo')

    def test_port(self):
        args = self.parser.parse_args(
            ['tls', '--hostname', 'foo', '--port', '123']
        )
        self.assertEqual(args.port, 123)

    def test_certfile(self):
        args = self.parser.parse_args(
            ['tls', '--hostname', 'foo', '--certfile', 'foo.cert']
        )
        self.assertEqual(args.certfile, 'foo.cert')

    def test_keyfile(self):
        args = self.parser.parse_args(
            ['tls', '--hostname', 'foo', '--keyfile', 'foo.key']
        )
        self.assertEqual(args.keyfile, 'foo.key')

    def test_cafile(self):
        args = self.parser.parse_args(
            ['tls', '--hostname', 'foo', '--cafile', 'foo.ca']
        )
        self.assertEqual(args.cafile, 'foo.ca')

    def test_no_credentials(self):
        args = self.parser.parse_args(
            ['tls', '--hostname', 'foo', '--no-credentials']
        )
        self.assertTrue(args.no_credentials)


class CustomizeParserTestCase(ParserTestCase):
    def test_add_optional_argument(self):
        self.parser.add_argument('--foo', type=int)

        args = self.parser.parse_args(['socket', '--foo', '123'])
        self.assertEqual(args.foo, 123)

        args = self.parser.parse_args(
            ['ssh', '--hostname', 'bar', '--foo', '123']
        )
        self.assertEqual(args.foo, 123)

        args = self.parser.parse_args(
            ['tls', '--hostname', 'bar', '--foo', '123']
        )
        self.assertEqual(args.foo, 123)

    def test_add_positional_argument(self):
        self.parser.add_argument('foo', type=int)
        args = self.parser.parse_args(['socket', '123'])

        self.assertEqual(args.foo, 123)

    def test_add_protocol_argument(self):
        self.parser.add_protocol_argument()

        args = self.parser.parse_args(['socket'])
        self.assertEqual(args.protocol, 'GMP')

        args = self.parser.parse_args(['--protocol', 'OSP', 'socket'])

        self.assertEqual(args.protocol, 'OSP')


class HelpFormattingParserTestCase(ParserTestCase):
    # pylint: disable=protected-access
    maxDiff = None
    python_version = '.'.join([str(i) for i in sys.version_info[:2]])

    def setUp(self):
        super().setUp()

        # ensure all tests are using the same terminal width
        self.columns = os.environ.get('COLUMNS')
        os.environ['COLUMNS'] = '80'

    def tearDown(self):
        super().tearDown()

        if not self.columns:
            del os.environ['COLUMNS']
        else:
            os.environ['COLUMNS'] = self.columns

    def _snapshot_specific_path(self, name):
        return __here__ / '{}.{}.snap'.format(name, self.python_version)

    def _snapshot_generic_path(self, name):
        return __here__ / '{}.snap'.format(name)

    def _snapshot_failed_path(self, name):
        return __here__ / '{}.{}-failed.snap'.format(name, self.python_version)

    def _snapshot_path(self, name):
        snapshot_specific_path = self._snapshot_specific_path(name)

        if snapshot_specific_path.exists():
            return snapshot_specific_path

        return self._snapshot_generic_path(name)

    def assert_snapshot(self, name, output):
        path = self._snapshot_path(name)

        if not path.exists():
            path.write_text(output)

        content = path.read_text()

        try:
            self.assertEqual(content, output, 'Snapshot differs from output')
        except AssertionError:
            # write new output to snapshot file
            # reraise error afterwards
            path = self._snapshot_failed_path(name)
            path.write_text(output)
            raise

    def test_root_help(self):
        help_output = self.parser._parser.format_help()
        self.assert_snapshot('root_help', help_output)

    def test_socket_help(self):
        help_output = self.parser._parser_socket.format_help()
        self.assert_snapshot('socket_help', help_output)

    def test_ssh_help(self):
        self.parser._set_defaults(None)
        help_output = self.parser._parser_ssh.format_help()
        self.assert_snapshot('ssh_help', help_output)

    def test_tls_help(self):
        self.parser._set_defaults(None)
        help_output = self.parser._parser_tls.format_help()
        self.assert_snapshot('tls_help', help_output)


class CreateParserFunctionTestCase(unittest.TestCase):
    # pylint: disable=protected-access
    def test_create_parser(self):
        description = 'parser description'
        logfilename = 'logfilename'

        parser = create_parser(description, logfilename)

        self.assertIsInstance(parser, CliParser)
        self.assertEqual(parser._logfilename, logfilename)
        self.assertEqual(parser._bootstrap_parser.description, description)


class CreateConnectionTestCase(unittest.TestCase):
    def test_create_unix_socket_connection(self):
        self.perform_create_connection_test()

    def test_create_tls_connection(self):
        self.perform_create_connection_test('tls', TLSConnection)

    def test_create_ssh_connection(self):
        self.perform_create_connection_test('ssh', SSHConnection, 22)

    def perform_create_connection_test(
        self,
        connection_type='socket',
        connection_class=UnixSocketConnection,
        port=None,
    ):
        connection = create_connection(connection_type, port=port)
        self.assertIsInstance(connection, connection_class)
