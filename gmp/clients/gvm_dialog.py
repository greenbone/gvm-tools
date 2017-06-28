# -*- coding: utf-8 -*-
# Description:
# GVM-Dialog for communication with the GVM.
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
import logging
import sys
from dialog import Dialog
from lxml import etree
from gmp.gvm_connection import (SSHConnection,
                                TLSConnection,
                                UnixSocketConnection)

__version__ = '1.1.0'

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        prog='gvm-dialog',
        add_help=False,
        epilog="""
usage: gvm-dialog [-h] [--version] [connection_type] ...
   or: gvm-dialog connection_type --help""")
    subparsers = parser.add_subparsers(metavar='[connection_type]')
    subparsers.required = True
    subparsers.dest = 'connection_type'

    parser.add_argument(
        '-h', '--help', action='help',
        help='Show this help message and exit.')

    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        '--timeout', required=False, default=60, type=int,
        help='Wait <seconds> for response. Default: 60')
    parent_parser.add_argument(
        '--log', nargs='?', dest='loglevel', const='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Activates logging. Default level: INFO.')
    parent_parser.add_argument(
        '-i', '--interactive', action='store_true', default=False,
        help='Start an interactive Python shell.')
    parent_parser.add_argument('--gmp-username', help='GMP username.')
    parent_parser.add_argument('--gmp-password', help='GMP password.')

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
        '--sockpath', nargs='?', default='/usr/local/var/run/gvmd.sock',
        help='UNIX-Socket path. Default: /usr/local/var/run/gvmd.sock.')

    parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {version}'.format(version=__version__),
        help='Show program\'s version number and exit')

    args = parser.parse_args()

    # Sets the logging
    if args.loglevel is not None:
        level = logging.getLevelName(args.loglevel)
        logging.basicConfig(filename='gvm-dialog.log', level=level)

    # Open the right connection. SSH at last for default
    global gmp
    if 'socket' in args.connection_type:
        try:
            gmp = UnixSocketConnection(sockpath=args.sockpath, shell_mode=True,
                                       timeout=args.timeout)
        except OSError as e:
            print('{0}: {1}'.format(e, args.sockpath))
            sys.exit(1)

    elif 'tls' in args.connection_type:
        try:
            gmp = TLSConnection(hostname=args.hostname, port=args.port,
                                timeout=args.timeout, shell_mode=True)
        except OSError as e:
            print('{0}: Host: {1} Port: {2}'.format(e, args.hostname,
                                                    args.port))
            sys.exit(1)
    else:
        try:
            gmp = SSHConnection(hostname=args.hostname, port=args.port,
                                timeout=args.timeout, ssh_user=args.ssh_user,
                                ssh_password='', shell_mode=True)
        except Exception as e:
            print('{0}: Host: {1} Port: {2}'.format(e, args.hostname,
                                                    args.port))
            sys.exit(1)

    d = Dialog(dialog="dialog")
    # Dialog.set_background_title() requires pythondialog 2.13 or later
    d.set_background_title("gvm-dialog")

    code, credentials = d.mixedform('Please enter credentials:', [
        # ('Hostname', 1, 1, '127.0.0.1', 1, 20, 15, 32, 0),
        ('Username', 1, 1, '', 1, 20, 15, 32, 0),
        ('Password', 2, 1, '', 2, 20, 15, 32, 1)], insecure=True)

    gmp.authenticate(credentials[0], credentials[1])

    code, tag = d.menu("What do you want to do?",
                       choices=[("(1)", "Show Tasks"),
                                ("(2)", "Exit")])
    if code == d.OK:
        # 'tag' is now either "(1)" or "(2)"

        if tag in '(1)':

            task_list = gmp.get_tasks()
            names = []
            tasks = dict()

            for task in task_list.xpath('task'):
                name = task.xpath('name/text()')[0]
                names.append((name, ''))
                tasks[name] = etree.tostring(
                    task, pretty_print=True).decode('utf-8')

            while(True):
                code, tag = d.menu("Tasks", choices=names)

                if 'cancel' in code:
                    break
                d.msgbox(tasks[tag], 60, 90)
        else:
            pass

    gmp.close()


def pretty(xml):
    """Prints beautiful XML-Code

    This function gets an object of list<lxml.etree._Element>
    or directly a lxml element.
    Print it with good readable format.

    Arguments:
        xml {obj} -- list<lxml.etree._Element> or directly a lxml element
    """
    if type(xml) is list:
        for item in xml:
            if etree.iselement(item):
                print(etree.tostring(item, pretty_print=True).decode('utf-8'))

            else:
                print(item)
    elif etree.iselement(xml):
        print(etree.tostring(xml, pretty_print=True).decode('utf-8'))

if __name__ == '__main__':
    main()
