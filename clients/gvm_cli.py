# -*- coding: utf-8 -*-
# Description:
# GVM-PyShell for communication with the GVM.
#
# Authors:
# Raphael Grewe <raphael.grewe@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
from argparse import RawTextHelpFormatter
import configparser
import getpass
import logging
import os.path
import sys

from libs.gvm_connection import (SSHConnection,
                                 TLSConnection,
                                 UnixSocketConnection)

__version__ = '0.2.dev1'

logger = logging.getLogger(__name__)

help_text = """
    gvm-cli {version} (C) 2017 Greenbone Networks GmbH

    This program is a command line tool to access services via
    GMP (Greenbone Management Protocol).

    Examples:
    gvm-cli --xml "<get_version/>"
    gvm-cli --xml "<commands><authenticate><credentials><username>myuser</username><password>mypass</password></credentials></authenticate><get_tasks/></commands>"
    gvm-cli < myfile.gmp
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
        description=help_text,
        formatter_class=RawTextHelpFormatter,
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
        '--log', nargs='?', dest='loglevel', const='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Activates logging. Default level: INFO.')
    parent_parser.add_argument('--gmp-username', help='GMP username.')
    parent_parser.add_argument('--gmp-password', help='GMP password.')
    parent_parser.add_argument('-X', '--xml', help='The XML request to send.')
    parent_parser.add_argument('infile', nargs='?', type=open,
                               default=sys.stdin)
    parent_parser.add_argument(
        '-c', '--config', nargs='?', const='~/.config/gvm-tools.conf',
        help='Configuration file path. Default: ~/.config/gvm-tools.conf')
    parser_ssh = subparsers.add_parser(
        'ssh', help='Use SSH connection for gmp service.',
        parents=[parent_parser])
    parser_ssh.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_ssh.add_argument('--port', required=False,
                            default=22, help='Port. Default: 22.')
    parser_ssh.add_argument('--ssh-user', default='gmp',
                            help='SSH Username. Default: gmp.')

    parser_tls = subparsers.add_parser(
        'tls', help='Use TLS secured connection for gmp service.',
        parents=[parent_parser])
    parser_tls.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_tls.add_argument('--port', required=False,
                            default=9390, help='Port. Default: 9390.')

    parser_socket = subparsers.add_parser(
        'socket', help='Use UNIX-Socket connection for gmp service.',
        parents=[parent_parser])
    parser_socket.add_argument(
        '--sockpath', nargs='?', default='/usr/local/var/run/openvasmd.sock',
        help='UNIX-Socket path. Default: /usr/local/var/run/openvasmd.sock.')

    parser.add_argument(
        '--version', action='version',
        version='%(prog)s {version}'.format(version=__version__),
        help='Show program\'s version number and exit')

    args = parser.parse_args()

    # Sets the logging
    if args.loglevel is not None:
        level = logging.getLevelName(args.loglevel)
        logging.basicConfig(filename='gvm-cli.log', level=level)

    # Looks for a config file
    if args.config is not None:
        try:
            config = configparser.ConfigParser()
            path = os.path.expanduser(args.config)

            config.read(path)
            auth = config['Auth']

            args.gmp_username = auth.get('gmp-username', 'admin')
            args.gmp_password = auth.get('gmp-password', 'admin')
        except Exception as message:
            print(message)

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

    if args.gmp_password is None:
        args.gmp_password = getpass.getpass('Please enter password for ' +
                                            args.gmp_username + ': ')

    # Open the right connection. SSH at last for default
    if args.sockpath is not None:
        connection_with_unix_socket(xml, args)
    elif args.tls:
        connection_direct_over_tls(xml, args)
    else:
        connection_over_ssh(xml, args)

    sys.exit(0)


def connection_with_unix_socket(xml, args):
    gvm = UnixSocketConnection(sockpath=args.sockpath)
    gvm.authenticate(args.gmp_username, args.gmp_password)
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


def connection_direct_over_tls(xml, args):
    gvm = TLSConnection(hostname=args.hostname, port=9390)
    gvm.authenticate(args.gmp_username, args.gmp_password)
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


def connection_over_ssh(xml, args):
    gvm = SSHConnection(hostname=args.hostname, port=args.port,
                        timeout=5, ssh_user=args.ssh_user, ssh_password='')
    gvm.authenticate(args.gmp_username, args.gmp_password)
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


if __name__ == '__main__':
    main()
