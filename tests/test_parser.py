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

from pathlib import Path

from gvm.connections import DEFAULT_UNIX_SOCKET_PATH, DEFAULT_TIMEOUT

from gvmtools.parser import CliParser

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

    def test_timeout(self):
        args = self.parser.parse_args(['--timeout', '1000', 'socket'])
        self.assertEqual(args.timeout, 1000)

    def test_gmp_username(self):
        args = self.parser.parse_args(['--gmp-username', 'foo', 'socket'])
        self.assertEqual(args.gmp_username, 'foo')

    def test_gmp_password(self):
        args = self.parser.parse_args(['--gmp-password', 'foo', 'socket'])
        self.assertEqual(args.gmp_password, 'foo')


class SocketParserTestCase(ParserTestCase):
    def test_defaults(self):
        args = self.parser.parse_args(['socket'])
        self.assertIsNone(args.sockpath)
        self.assertEqual(args.socketpath, '/usr/local/var/run/gvmd.sock')

    def test_connection_type(self):
        args = self.parser.parse_args(['socket'])
        self.assertEqual(args.connection_type, 'socket')

    def test_sockpath(self):
        args = self.parser.parse_args(['socket', '--sockpath', 'foo.sock'])
        self.assertEqual(args.sockpath, 'foo.sock')

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

    def _snapshot_path(self, name):
        return __here__ / '{}.snap'.format(name)

    def _load_snapshot(self, path):
        return path.read_text()

    def _write_snapshot(self, path, output):
        path.write_text(output)

    def assert_snapshot(self, name, output):
        path = self._snapshot_path(name)

        if not path.exists():
            path.write_text(output)

        content = path.read_text()
        self.assertEqual(content, output, 'Snapshot differs from output')

    def test_root_help(self):
        help_output = self.parser._parser.format_help()
        self.assert_snapshot('root_help', help_output)

    def test_socket_help(self):
        help_output = self.parser._parser_socket.format_help()
        self.assert_snapshot('socket_help', help_output)

    def test_ssh_help(self):
        help_output = self.parser._parser_ssh.format_help()
        self.assert_snapshot('ssh_help', help_output)

    def test_tls_help(self):
        help_output = self.parser._parser_tls.format_help()
        self.assert_snapshot('tls_help', help_output)
