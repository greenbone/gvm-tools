# -*- coding: utf-8 -*-
# Copyright (C) 2018-2021 Greenbone Networks GmbH
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
import logging

from pathlib import Path

from gvm import get_version as get_gvm_version
from gvm.connections import (
    DEFAULT_TIMEOUT,
    SSHConnection,
    TLSConnection,
    UnixSocketConnection,
)

from gvmtools import get_version
from gvmtools.config import Config

logger = logging.getLogger(__name__)

__version__ = get_version()
__api_version__ = get_gvm_version()

DEFAULT_CONFIG_PATH = '~/.config/gvm-tools.conf'

PROTOCOL_OSP = 'OSP'
PROTOCOL_GMP = 'GMP'
DEFAULT_PROTOCOL = PROTOCOL_GMP


class CliParser:
    def __init__(
        self, description, logfilename, *, prog=None, ignore_config=False
    ):
        bootstrap_parser = argparse.ArgumentParser(
            prog=prog,
            description=description,
            formatter_class=argparse.RawTextHelpFormatter,
            # don't parse help initially. the args from parser wouldn't be shown
            add_help=False,
        )

        bootstrap_parser.add_argument(
            '-c',
            '--config',
            nargs='?',
            default=DEFAULT_CONFIG_PATH,
            help='Configuration file path (default: %(default)s)',
        )

        choices = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

        bootstrap_parser.add_argument(
            '--log',
            nargs='?',
            dest='loglevel',
            const='INFO',
            type=lambda arg: {x.upper(): x for x in choices}[arg.upper()],
            choices=choices,
            help='Activate logging (default level: %(default)s)',
        )

        parser = argparse.ArgumentParser(prog=prog, parents=[bootstrap_parser])

        parser.add_argument(
            '--timeout',
            required=False,
            default=DEFAULT_TIMEOUT,
            type=int,
            help='Response timeout in seconds, or -1 to wait '
            'indefinitely (default: %(default)s)',
        )
        parser.add_argument(
            '--gmp-username',
            help='Username for GMP service (default: %(default)r)',
        )
        parser.add_argument(
            '--gmp-password',
            help='Password for GMP service (default: %(default)r)',
        )
        parser.add_argument(
            '-V',
            '--version',
            action='version',
            version='%(prog)s {version} (API version {apiversion})'.format(
                version=__version__, apiversion=__api_version__
            ),
            help='Show version information and exit',
        )

        subparsers = parser.add_subparsers(
            metavar='CONNECTION_TYPE',
            title='connections',
            description='valid connection types',
            help="Connection type to use",
        )
        subparsers.required = True
        subparsers.dest = 'connection_type'

        self._subparsers = subparsers

        self._parser = parser
        self._bootstrap_parser = bootstrap_parser

        self._logfilename = logfilename
        self._ignore_config = ignore_config

        self._add_subparsers()

    def parse_args(self, args=None):
        args, unkown_args = self.parse_known_args(args)
        if unkown_args:
            self._parser.error(
                'unrecognized arguments {}'.format(' '.join(unkown_args))
            )
        return args

    def parse_known_args(self, args=None):
        args_before, _ = self._bootstrap_parser.parse_known_args(args)

        if args_before.loglevel is not None:
            level = logging.getLevelName(args_before.loglevel)
            logging.basicConfig(filename=self._logfilename, level=level)

        self._set_defaults(None if self._ignore_config else args_before.config)

        args, unknown_args = self._parser.parse_known_args(args)

        # If timeout value is -1, then the socket should have no timeout
        if args.timeout == -1:
            args.timeout = None

        logging.debug('Parsed arguments %r', args)

        return args, unknown_args

    def add_argument(self, *args, **kwargs):
        self._parser_socket.add_argument(*args, **kwargs)
        self._parser_ssh.add_argument(*args, **kwargs)
        self._parser_tls.add_argument(*args, **kwargs)

    def add_protocol_argument(self):
        self._parser.add_argument(
            '--protocol',
            required=False,
            default=DEFAULT_PROTOCOL,
            choices=[PROTOCOL_GMP, PROTOCOL_OSP],
            help='Service protocol to use (default: %(default)s)',
        )

    def _load_config(self, configfile):
        config = Config()

        if not configfile:
            return config

        configpath = Path(configfile)

        try:
            if not configpath.expanduser().resolve().exists():
                logger.debug('Ignoring non existing config file %s', configfile)
                return config
        except FileNotFoundError:
            # we are on python 3.5 and Path.resolve raised a FileNotFoundError
            logger.debug('Ignoring non existing config file %s', configfile)
            return config

        try:
            config.load(configpath)
            logger.debug('Loaded config %s', configfile)
        except Exception as e:  # pylint: disable=broad-except
            raise RuntimeError(
                'Error while parsing config file {config}. Error was '
                '{message}'.format(config=configfile, message=e)
            ) from None

        return config

    def _add_subparsers(self):
        parser_ssh = self._subparsers.add_parser(
            'ssh', help='Use SSH to connect to service'
        )

        parser_ssh.add_argument(
            '--hostname', help='Hostname or IP address (default: %(default)s)'
        )
        parser_ssh.add_argument(
            '--port',
            required=False,
            help='SSH port (default: %(default)s)',
            type=int,
        )
        parser_ssh.add_argument(
            '--ssh-username', help='SSH username (default: %(default)r)'
        )
        parser_ssh.add_argument(
            '--ssh-password', help='SSH password (default: %(default)r)'
        )

        parser_tls = self._subparsers.add_parser(
            'tls', help='Use TLS secured connection to connect to service'
        )
        parser_tls.add_argument(
            '--hostname', help='Hostname or IP address (default: %(default)s)'
        )
        parser_tls.add_argument(
            '--port',
            required=False,
            help='GMP/OSP port (default: %(default)s)',
            type=int,
        )
        parser_tls.add_argument(
            '--certfile',
            required=False,
            help='Path to the certificate file for client authentication. '
            '(default: %(default)s)',
        )
        parser_tls.add_argument(
            '--keyfile',
            required=False,
            help='Path to key file for client authentication. '
            '(default: %(default)s)',
        )
        parser_tls.add_argument(
            '--cafile',
            required=False,
            help='Path to CA certificate for server authentication. '
            '(default: %(default)s)',
        )
        parser_tls.add_argument(
            '--no-credentials',
            required=False,
            default=False,
            action='store_true',
            help='Use only certificates for authentication',
        )

        parser_socket = self._subparsers.add_parser(
            'socket', help='Use UNIX Domain socket to connect to service'
        )

        socketpath_group = parser_socket.add_mutually_exclusive_group()
        socketpath_group.add_argument(
            '--sockpath',
            nargs='?',
            default=None,
            dest='socketpath',
            help='Deprecated, use --socketpath instead',
        )
        socketpath_group.add_argument(
            '--socketpath',
            nargs='?',
            help='Path to UNIX Domain socket (default: %(default)s)',
        )

        self._parser_ssh = parser_ssh
        self._parser_socket = parser_socket
        self._parser_tls = parser_tls

    def _set_defaults(self, configfilename=None):
        self._config = self._load_config(configfilename)

        self._parser.set_defaults(
            gmp_username=self._config.get('gmp', 'username'),
            gmp_password=self._config.get('gmp', 'password'),
            **self._config.defaults(),
        )

        self._parser_ssh.set_defaults(
            port=int(self._config.get('ssh', 'port')),
            ssh_username=self._config.get('ssh', 'username'),
            ssh_password=self._config.get('ssh', 'password'),
            hostname=self._config.get('ssh', 'hostname'),
        )
        self._parser_tls.set_defaults(
            port=int(self._config.get('tls', 'port')),
            certfile=self._config.get('tls', 'certfile'),
            keyfile=self._config.get('tls', 'keyfile'),
            cafile=self._config.get('tls', 'cafile'),
            hostname=self._config.get('tls', 'hostname'),
        )
        self._parser_socket.set_defaults(
            socketpath=self._config.get('unixsocket', 'socketpath')
        )


def create_parser(description, logfilename):
    return CliParser(description, logfilename)


def create_connection(
    connection_type,
    socketpath=None,
    timeout=None,
    hostname=None,
    port=None,
    certfile=None,
    keyfile=None,
    cafile=None,
    ssh_username=None,
    ssh_password=None,
    **kwargs  # pylint: disable=unused-argument
):
    if 'socket' in connection_type:
        return UnixSocketConnection(timeout=timeout, path=socketpath)

    if 'tls' in connection_type:
        return TLSConnection(
            timeout=timeout,
            hostname=hostname,
            port=port,
            certfile=certfile,
            keyfile=keyfile,
            cafile=cafile,
        )

    return SSHConnection(
        timeout=timeout,
        hostname=hostname,
        port=port,
        username=ssh_username,
        password=ssh_password,
    )
