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

import argparse
import configparser
import getpass
import logging
import os.path
import sys

from gmp import get_version
from gmp.protocols.latest import Gmp
from gmp.connection import (SSHConnection,
                            TLSConnection,
                            UnixSocketConnection,
                            DEFAULT_UNIX_SOCKET_PATH,
                            DEFAULT_TIMEOUT,
                            DEFAULT_GVM_PORT)
from gmp.transform import CheckCommandTransform

__version__ = get_version()

logger = logging.getLogger(__name__)

HELP_TEXT = """
    gvm-cli {version} (C) 2017 Greenbone Networks GmbH

    This program is a command line tool to access services via
    GMP (Greenbone Management Protocol).

    Examples:

    gvm-cli socket --xml "<get_version/>"
    gvm-cli socket --xml "<commands><authenticate><credentials><username>myuser</username><password>mypass</password></credentials></authenticate><get_tasks/></commands>"
    gvm-cli socket --gmp-username foo --gmp-password foo < myfile.xml

    Further Information about GMP see here:
    http://docs.greenbone.net/index.html#api_documentation
    Note: "GMP" was formerly known as "OMP".

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    """.format(version=__version__)


def main():

    parser = argparse.ArgumentParser(
        prog='gvm-cli',
        description=HELP_TEXT,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        epilog="""
usage: gvm-cli [-h] [--version] [connection_type] ...
   or: gvm-cli connection_type --help""")

    subparsers = parser.add_subparsers(metavar='[connection_type]')
    subparsers.required = True
    subparsers.dest = 'connection_type'

    parser.add_argument(
        '-h', '--help', action='help',
        help='Show this help message and exit.')

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        '-c', '--config', nargs='?', const='~/.config/gvm-tools.conf',
        help='Configuration file path. Default: ~/.config/gvm-tools.conf')
    args, remaining_args = parent_parser.parse_known_args()

    defaults = {
        'gmp_username': '',
        'gmp_password': ''
    }

    # Retrieve data from config file
    if args.config:
        try:
            config = configparser.SafeConfigParser()
            path = os.path.expanduser(args.config)
            config.read(path)
            defaults = dict(config.items('Auth'))
        except Exception as e: # pylint: disable=broad-except
            print(str(e))

    parent_parser.set_defaults(**defaults)

    parent_parser.add_argument(
        '--timeout', required=False, default=DEFAULT_TIMEOUT, type=int,
        help='Wait <seconds> for response or if value is -1, then wait '
             'indefinitely. Default: %(default)s.')
    parent_parser.add_argument(
        '--log', nargs='?', dest='loglevel', const='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Activates logging. Default level: %(default)s.')
    parent_parser.add_argument('--gmp-username', help='GMP username.')
    parent_parser.add_argument('--gmp-password', help='GMP password.')
    parent_parser.add_argument('-X', '--xml', help='The XML request to send.')
    parent_parser.add_argument('-r', '--raw', help='Return raw XML.',
                               action='store_true', default=False)
    parent_parser.add_argument('infile', nargs='?', type=open,
                               default=sys.stdin)
    parser_ssh = subparsers.add_parser(
        'ssh', help='Use SSH connection for gmp service.',
        parents=[parent_parser])
    parser_ssh.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_ssh.add_argument('--port', required=False,
                            default=22, help='Port. Default: %(default)s.')
    parser_ssh.add_argument('--ssh-user', default='gmp',
                            help='SSH Username. Default: %(default)s.')
    parser_ssh.add_argument('--ssh-password', default='gmp',
                            help='SSH Password. Default: %(default)s.')


    parser_tls = subparsers.add_parser(
        'tls', help='Use TLS secured connection for gmp service.',
        parents=[parent_parser])
    parser_tls.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_tls.add_argument('--port', required=False,
                            default=DEFAULT_GVM_PORT,
                            help='Port. Default: %(default)s.')
    parser_tls.add_argument('--certfile', required=False, default=None,
                            help='Path to the certificate file.')
    parser_tls.add_argument('--keyfile', required=False, default=None,
                            help='Path to key certificate file.')
    parser_tls.add_argument('--cafile', required=False, default=None,
                            help='Path to CA certificate file.')

    parser_socket = subparsers.add_parser(
        'socket', help='Use UNIX-Socket connection for gmp service.',
        parents=[parent_parser])
    parser_socket.add_argument(
        '--sockpath', nargs='?', default=None,
        help='Depreacted. Use --socketpath instead')
    parser_socket.add_argument(
        '--socketpath', nargs='?', default=DEFAULT_UNIX_SOCKET_PATH,
        help='UNIX-Socket path. Default: %(default)s.')

    parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {version}'.format(version=__version__),
        help='Show program\'s version number and exit')

    args = parser.parse_args(remaining_args)

    # Sets the logging
    if args.loglevel is not None:
        level = logging.getLevelName(args.loglevel)
        logging.basicConfig(filename='gvm-cli.log', level=level)

    # If timeout value is -1, then the socket has no timeout for this session
    if args.timeout == -1:
        args.timeout = None

    xml = ''

    if args.xml is not None:
        xml = args.xml
    else:
        # If this returns False, then some data are in sys.stdin
        if not args.infile.isatty():
            try:
                xml = args.infile.read()
            except (EOFError, BlockingIOError) as e:
                print(e)

    # If no command was given, program asks for one
    if len(xml) == 0:
        xml = input()

    # Remove all newlines if the commands come from file
    xml = xml.replace('\n', '').replace('\r', '')

    # Ask for password if none are given
    if args.gmp_username and not args.gmp_password:
        args.gmp_password = getpass.getpass('Enter password for ' +
                                            args.gmp_username + ': ')

    # Open the right connection. SSH at last for default
    if 'socket' in args.connection_type:
        socketpath = args.sockpath
        if socketpath is None:
            socketpath = args.socketpath
        else:
            print('The --sockpath parameter has been deprecated. Please use '
                  '--socketpath instead', file=sys.stderr)

        connection = UnixSocketConnection(
            timeout=args.timeout,
            path=socketpath
        )
    elif 'tls' in args.connection_type:
        connection = TLSConnection(
            timeout=args.timeout,
            hostname=args.hostname,
            port=args.port,
            certfile=args.certfile,
            keyfile=args.keyfile,
            cafile=args.cafile,
        )
    else:
        connection = SSHConnection(
            timeout=args.timeout,
            hostname=args.hostname,
            port=args.port,
            username=args.ssh_user,
            password=args.ssh_password
        )

    if args.raw:
        transform = None
    else:
        transform = CheckCommandTransform()

    gvm = Gmp(connection, transform=transform)

    if args.gmp_username:
        gvm.authenticate(args.gmp_username, args.gmp_password)

    try:
        result = gvm.send_command(xml)

        print(result)
    except Exception as e: # pylint: disable=broad-except
        print(e)
        sys.exit(1)

    gvm.disconnect()

    sys.exit(0)


if __name__ == '__main__':
    main()
