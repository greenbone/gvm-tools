# -*- coding: utf-8 -*-
# $Id$
# Description:
# GVM-Cli for communication with the GVM UNIX-Socket over SSH.
#
# Authors:
# Raphael Grewe <raphael.grewe@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
from argparse import RawTextHelpFormatter
import configparser
import os.path
import socket
import ssl
import sys
import time


from gmp import _gmp
from gvm_connection import GVMConnection

help_text = """     
    gvm-cli 0.1.0 (C) 2017 Greenbone Networks GmbH

    This program is a command line tool to access services via
    GMP (Greenbone Management Protocol).

    Examples:
    gvm-cli --xml "<get_version/>"
    gvm-cli --xml "<commands><authenticate><credentials><username>myuser</username><password>mypass</password></credentials></authenticate><get_tasks/></commands>"
    gvm-cli < myfile.gmp
    Further Information about GMP see here:
    http://docs.greenbone.net/API/OMP/omp-7.0.html
    Note: "GMP" was formerly known as "OMP".
    """


def main(argv):
    """ssh_credentials = {'ssh_hostname': argv.hostname,
                       'ssh_port': argv.port, 'ssh_user': argv.ssh_user}
    gvm_credentials = {'gmp_username': argv.gmp_username,
                       'gmp_password': argv.gmp_password}
    """
    xml = ''

    if argv.xml != None:
        xml = argv.xml
    else:
        # If this returns False, then some data are in sys.stdin
        if not argv.infile.isatty():
            try:
                xml = argv.infile.read()
            except (EOFError, BlockingIOError) as e:
                print(e)

    if len(xml) == 0:
        xml = input()

    # Remove all newlines if the commands come from file
    xml = xml.replace('\n', '').replace('\r', '')

    if argv.socket != None:
        connection_with_unix_socket(xml, argv)
    elif argv.tls:
        connection_direct_over_tls(xml, argv)
    else:
        connection_over_ssh(xml, argv)

    sys.exit(0)


def connection_with_unix_socket(xml, argv):
    gvm = GVMConnection(GVMConnection.UNIX_SOCKET, argv)
    gvm.authenticate()
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


def connection_direct_over_tls(xml, argv):
    gvm = GVMConnection(GVMConnection.TLS, argv)
    gvm.authenticate()
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


def connection_over_ssh(xml, argv):
    gvm = GVMConnection(GVMConnection.SSH, argv)
    gvm.authenticate()
    gvm.send(xml)

    result = gvm.read()
    print(result)
    gvm.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='gvm-cli',
        description=help_text,
        formatter_class=RawTextHelpFormatter,
        add_help=False,
        usage='gvm-cli [--help] [--hostname HOSTNAME] [--port PORT] [--xml XML]')
    parser.add_argument('-h', '--help', action='help',
                        help='Show this help message and exit.')
    parser.add_argument('-c', '--config', nargs='?', const='~/.config/gvm-tools.conf',
                        help='Path to the configuration file. Default: ~/.config/gvm-tools.conf')
    parser.add_argument('--hostname', default='127.0.0.1',
                        help='SSH hostname or IP-Address. Default: 127.0.0.1.')
    parser.add_argument('--tls', action='store_true',
                        help='Use TLS secured connection for omp service.')
    parser.add_argument('--port', default=22, help='SSH port. Default: 22.')
    parser.add_argument('--ssh-user', default='gmp',
                        help='SSH username. Default: gmp.')
    parser.add_argument('--gmp-username', default='admin',
                        help='GMP username. Default: admin')
    parser.add_argument('--gmp-password', nargs='?', const='admin',
                        help='GMP password. Default: admin.')
    parser.add_argument('--socket', nargs='?', const='/usr/local/var/run/openvasmd.sock',
                        help='Path to UNIX-Socket. Default: /usr/local/var/run/openvasmd.sock.')
    parser.add_argument('-X', '--xml', help='The XML request to send.')
    parser.add_argument('infile', nargs='?', type=open, default=sys.stdin)

    args = parser.parse_args()

    if args.config != None:
        try:
            config = configparser.ConfigParser()
            path = os.path.expanduser(args.config)

            config.read(path)
            auth = config['Auth']

            args.gmp_username = auth.get('gmp-username', 'admin')
            args.gmp_password = auth.get('gmp-password', 'admin')
        except Exception as message:
            print(message)

    main(args)
