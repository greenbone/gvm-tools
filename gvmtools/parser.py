# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
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

"""Command Line Interface Parser
"""

import argparse
import configparser
import logging
import os

from gvm import get_version as get_gvm_version
from gvm.connections import (DEFAULT_UNIX_SOCKET_PATH,
                             DEFAULT_TIMEOUT,
                             DEFAULT_GVM_PORT)

from gvmtools import get_version

logger = logging.getLogger(__name__)

__version__ = get_version()
__api_version__ = get_gvm_version()

DEFAULT_CONFIG_PATH = '~/.config/gvm-tools.conf'


class CliParser:

    def __init__(self, description, logfilename):
        root_parser = argparse.ArgumentParser(
            description=description,
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False)

        root_parser.add_argument(
            '-c', '--config', nargs='?', default=DEFAULT_CONFIG_PATH,
            help='Configuration file path (default: %(default)s)')
        root_parser.add_argument(
            '--log', nargs='?', dest='loglevel', const='INFO',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            help='Activate logging (default level: %(default)s)')

        args_before, remaining_args = root_parser.parse_known_args()

        if args_before.loglevel is not None:
            level = logging.getLevelName(args_before.loglevel)
            logging.basicConfig(filename=logfilename, level=level)

        defaults = self._get_defaults(args_before.config)

        root_parser.add_argument(
            '--timeout', required=False, default=DEFAULT_TIMEOUT, type=int,
            help='Response timeout in seconds, or -1 to wait '
                 'indefinitely (default: %(default)s)')
        root_parser.add_argument(
            '-i', '--interactive', action='store_true', default=False,
            help='Start an interactive Python shell')
        root_parser.add_argument(
            '--gmp-username',
            help='Username for GMP service (default: %(default)r)')
        root_parser.add_argument(
            '--gmp-password',
            help='Password for GMP service (default: %(default)r)')
        root_parser.add_argument(
            '-V', '--version', action='version',
            version='%(prog)s {version} (API version {apiversion})'.format(
                version=__version__, apiversion=__api_version__),
            help='Show version information and exit')

        parser = argparse.ArgumentParser(parents=[root_parser])
        parser.set_defaults(**defaults)

        subparsers = parser.add_subparsers(
            metavar='CONNECTION_TYPE',
            title='connections',
            description='valid connection types',
            help="Connection type to use",
        )
        subparsers.required = True
        subparsers.dest = 'connection_type'

        self._parser = parser
        self._root_parser = root_parser
        self._subparsers = subparsers
        self._remaining_args = remaining_args

    def parse_args(self):
        self._add_subparsers()
        return self._parser.parse_args(self._remaining_args)

    def add_argument(self, *args, **kwargs):
        self._parser.add_argument(*args, **kwargs)
        self._root_parser.add_argument(*args, **kwargs)

    def _get_defaults(self, configfile):
        defaults = {
            'gmp_username': '',
            'gmp_password': '',
        }

        if not configfile:
            return defaults

        try:
            config = configparser.SafeConfigParser()
            path = os.path.expanduser(configfile)
            config.read(path)
            defaults = dict(config.items('Auth'))
        except configparser.NoSectionError:
            pass
        except Exception as e: # pylint: disable=broad-except
            raise RuntimeError(
                'Error while parsing config file {config}. Error was '
                '{message}'.format(config=configfile, message=e))

        return defaults

    def _add_subparsers(self):
        parser_ssh = self._subparsers.add_parser(
            'ssh', help='Use SSH to connect to service',
            parents=[self._root_parser])

        parser_ssh.add_argument('--hostname', required=True,
                                help='Hostname or IP address')
        parser_ssh.add_argument('--port', required=False, default=22,
                                help='SSH port (default: %(default)s)')
        parser_ssh.add_argument('--ssh-user', default='gmp',
                                help='SSH username (default: %(default)s)')

        parser_tls = self._subparsers.add_parser(
            'tls', help='Use TLS secured connection to connect to service',
            parents=[self._root_parser])
        parser_tls.add_argument('--hostname', required=True,
                                help='Hostname or IP address')
        parser_tls.add_argument('--port', required=False,
                                default=DEFAULT_GVM_PORT,
                                help='GMP/OSP port (default: %(default)s)')
        parser_tls.add_argument(
            '--certfile', required=False, default=None,
            help='Path to the certificate file for client authentication')
        parser_tls.add_argument(
            '--keyfile', required=False, default=None,
            help='Path to key file for client authentication')
        parser_tls.add_argument(
            '--cafile', required=False, default=None,
            help='Path to CA certificate for server authentication')
        parser_tls.add_argument(
            '--no-credentials', required=False, default=False,
            help='Use only certificates for authentication')

        parser_socket = self._subparsers.add_parser(
            'socket', help='Use UNIX Domain socket to connect to service',
            parents=[self._root_parser])
        parser_socket.add_argument(
            '--sockpath', nargs='?', default=None,
            help='Deprecated, use --socketpath instead')
        parser_socket.add_argument(
            '--socketpath', nargs='?', default=DEFAULT_UNIX_SOCKET_PATH,
            help='Path to UNIX Domain socket (default: %(default)s)')



def create_parser(description, logfilename):
    return CliParser(description, logfilename)
