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
import logging
import unittest

from pathlib import Path

from gvm.connections import DEFAULT_UNIX_SOCKET_PATH, DEFAULT_GVM_PORT

from gvmtools.config import Config, DEFAULT_SSH_PORT, __name__ as name

__here__ = Path(__file__).parent.resolve()


class ConfigTestCase(unittest.TestCase):
    def test_config_defaults(self):
        config = Config()

        self.assertEqual(config.get('gmp', 'username'), '')
        self.assertEqual(config.get('gmp', 'password'), '')

        self.assertEqual(config.get('ssh', 'username'), 'gmp')
        self.assertEqual(config.get('ssh', 'password'), 'gmp')
        self.assertEqual(config.get('ssh', 'port'), DEFAULT_SSH_PORT)

        self.assertEqual(
            config.get('unixsocket', 'socketpath'), DEFAULT_UNIX_SOCKET_PATH
        )

        self.assertEqual(config.get('tls', 'port'), DEFAULT_GVM_PORT)

    def test_get_unknown_setting(self):
        config = Config()
        self.assertIsNone(config.get('foo', 'bar'))

    def test_load(self):
        test_config_path = __here__ / 'test.cfg'

        self.assertTrue(test_config_path.is_file())

        config = Config()
        config.load(test_config_path)

        self.assertEqual(config.get('gmp', 'username'), 'bar')
        self.assertEqual(config.get('gmp', 'password'), 'bar')

        self.assertEqual(config.get('ssh', 'username'), 'ipsum')
        self.assertEqual(config.get('ssh', 'password'), 'lorem')
        self.assertEqual(config.get('ssh', 'port'), '123')

        self.assertEqual(
            config.get('unixsocket', 'socketpath'), '/foo/bar.sock'
        )

        self.assertEqual(config.get('tls', 'port'), '123')
        self.assertEqual(config.get('tls', 'certfile'), 'foo.cert')
        self.assertEqual(config.get('tls', 'keyfile'), 'foo.key')
        self.assertEqual(config.get('tls', 'cafile'), 'foo.ca')

        self.assertDictEqual(
            config.defaults(), dict(timeout='1000', foo='bar', username='ipsum')
        )

    def test_load_auth(self):
        root = logging.getLogger(name)
        root.disabled = True

        test_config_path = __here__ / 'test_auth.cfg'

        self.assertTrue(test_config_path.is_file())

        config = Config()
        config.load(test_config_path)

        self.assertEqual(config.get('gmp', 'username'), 'foo')
        self.assertEqual(config.get('gmp', 'password'), 'bar')

        root.disabled = False

    def test_load_with_non_existing_configfile(self):
        test_config_path = __here__ / 'foo.cfg'

        self.assertFalse(test_config_path.is_file())

        config = Config()

        with self.assertRaises(FileNotFoundError):
            config.load(test_config_path)
