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
"""
Module to store gvm-tools configuration settings
"""

import configparser
import logging

from gvm.connections import (
    DEFAULT_UNIX_SOCKET_PATH,
    DEFAULT_GVM_PORT,
    DEFAULT_SSH_PORT,
    DEFAULT_HOSTNAME,
)

logger = logging.getLogger(__name__)


class Config:
    def __init__(self):
        self._config = configparser.ConfigParser(default_section='main')

        self._config = {}

        self._config['gmp'] = dict(username='', password='')
        self._config['ssh'] = dict(
            username='gmp',
            password='gmp',
            port=DEFAULT_SSH_PORT,
            hostname=DEFAULT_HOSTNAME,
        )
        self._config['unixsocket'] = dict(socketpath=DEFAULT_UNIX_SOCKET_PATH)
        self._config['tls'] = dict(
            port=DEFAULT_GVM_PORT, hostname=DEFAULT_HOSTNAME
        )

        self._defaults = dict()

    def load(self, filepath):
        path = filepath.expanduser()

        config = configparser.ConfigParser(default_section='main')

        with path.open() as f:
            config.read_file(f)

        if 'Auth' in config:
            logger.warning(
                "Warning: Loaded config file %s contains deprecated 'Auth' "
                "section. This section will be ignored in future.",
                str(filepath),
            )
            gmp_username = config.get('Auth', 'gmp_username', fallback='')
            gmp_password = config.get('Auth', 'gmp_password', fallback='')
            self._config['gmp']['username'] = gmp_username
            self._config['gmp']['password'] = gmp_password

        self._defaults.update(config.defaults())

        for section in config.sections():
            if section == 'Auth':
                continue

            for key, value in config.items(section):
                self._config.setdefault(section, dict())[key] = value

    def defaults(self):
        return self._defaults

    def get(self, section, name):
        if not section in self._config:
            return None

        return self._config[section].get(name)
