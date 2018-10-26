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
import code
import configparser
import getpass
import logging
import os
import sys

from lxml import etree

from gmp import Gmp, get_version
from gmp.connection import (SSHConnection,
                            TLSConnection,
                            UnixSocketConnection,
                            DEFAULT_UNIX_SOCKET_PATH,
                            DEFAULT_TIMEOUT,
                            DEFAULT_GVM_PORT)
from gmp.transform import EtreeCheckCommandTransform


__version__ = get_version()

logger = logging.getLogger(__name__)

help_text = """
    gvm-pyshell {version} (C) 2017 Greenbone Networks GmbH

    This program is a command line tool to access services
    via GMP(Greenbone Management Protocol) and
    OSP(Open Scanner Protocol).
    It is possible to start a shell like the python interactive
    mode where you could type things like "tasks = gmp.get_task".

    At the moment only these commands are support in the interactive shell:

    gmp.get_version()
    gmp.authenticate([username], [password])
    gmp.get_tasks()
    gmp.get_reports()
    gmp.get_results()
    gmp.get_assets()
    gmp.get_port_lists()

    Example:
        gmp.authenticate('admin', 'admin')
        tasks = gmp.get_tasks()

        list = tasks.xpath('task')

        taskid = list[0].attrib

        load('my_commands.gmp')

    Good introduction in working with XPath is well described here:
    https://www.w3schools.com/xml/xpath_syntax.asp

    To get out of the shell enter:
        Ctrl + D on Linux  or
        Ctrl + Z on Windows

    Further Information about the GMP Protocol can be found at:
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


class Help(object):
    """Help class to overwrite the help function from python itself.
    """

    def __repr__(self):
        # do pwd command
        return help_text
help = Help()

# gmp has to be global, so the load-function has the correct namespace
gmp = None


def main():
    parser = argparse.ArgumentParser(
        prog='gvm-pyshell',
        description=help_text,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        epilog="""
usage: gvm-pyshell [-h] [--version] [connection_type] ...
   or: gvm-pyshell connection_type --help""")
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
    args_before, remaining_args = parent_parser.parse_known_args()

    defaults = {
        'gmp_username': '',
        'gmp_password': ''
    }

    # Retrieve data from config file
    if args_before.config:
        try:
            config = configparser.SafeConfigParser()
            path = os.path.expanduser(args_before.config)
            config.read(path)
            defaults = dict(config.items('Auth'))
        except Exception as e:
            print(str(e))

    parent_parser.set_defaults(**defaults)

    parent_parser.add_argument(
        '--timeout', required=False, default=DEFAULT_TIMEOUT, type=int,
        help='Wait <seconds> for response or if value -1, then wait '
             'continuously. Default: %(default)s')
    parent_parser.add_argument(
        '--log', nargs='?', dest='loglevel', const='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Activates logging. Default level: INFO.')
    parent_parser.add_argument(
        '-i', '--interactive', action='store_true', default=False,
        help='Start an interactive Python shell.')
    parent_parser.add_argument('--gmp-username', help='GMP username.')
    parent_parser.add_argument('--gmp-password', help='GMP password.')
    parent_parser.add_argument(
        'script', nargs='*',
        help='Preload gmp script. Example: myscript.gmp.')

    parser_ssh = subparsers.add_parser(
        'ssh', help='Use SSH connection for gmp service.',
        parents=[parent_parser])
    parser_ssh.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_ssh.add_argument('--port', required=False,
                            default=22, help='Port. Default: %(default)s.')
    parser_ssh.add_argument('--ssh-user', default='gmp',
                            help='SSH Username. Default: %(default)s.')

    parser_tls = subparsers.add_parser(
        'tls', help='Use TLS secured connection for gmp service.',
        parents=[parent_parser])
    parser_tls.add_argument('--hostname', required=True,
                            help='Hostname or IP-Address.')
    parser_tls.add_argument('--port', required=False,
                            default=DEFAULT_GVM_PORT,
                            help='Port. Default: %(default)s.')

    parser_socket = subparsers.add_parser(
        'socket', help='Use UNIX-Socket connection for gmp service.',
        parents=[parent_parser])
    parser_socket.add_argument(
        '--sockpath', nargs='?', default=DEFAULT_UNIX_SOCKET_PATH,
        help='Depreacted. Use --socketpath instead')
    parser_socket.add_argument(
        '--socketpath', nargs='?', default=DEFAULT_UNIX_SOCKET_PATH,
        help='UNIX-Socket path. Default: %(default)s.')

    parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {version}'.format(version=__version__),
        help='Show program\'s version number and exit')

    global args
    args = parser.parse_args(remaining_args)

    # Sets the logging
    if args.loglevel is not None:
        level = logging.getLevelName(args.loglevel)
        logging.basicConfig(filename='gvm-pyshell.log', level=level)

    # If timeout value is -1, then the socket has no timeout for this session
    if args.timeout == -1:
        args.timeout = None

    # Open the right connection. SSH at last for default
    if 'socket' in args.connection_type:
        socketpath = args.socketpath
        if socketpath is None:
            socketpath = args.sockpath

        connection = UnixSocketConnection(path=socketpath,
                                          timeout=args.timeout)
    elif 'tls' in args.connection_type:
        connection = TLSConnection(hostname=args.hostname, port=args.port,
                                   timeout=args.timeout)
    else:
        connection = SSHConnection(hostname=args.hostname, port=args.port,
                                   timeout=args.timeout, username=args.ssh_user,
                                   password='')

    # Ask for login credentials if none are given
    if not args.gmp_username:
        while len(args.gmp_username) == 0:
            args.gmp_username = input('Enter username: ')

    if not args.gmp_password:
        args.gmp_password = getpass.getpass(
            'Enter password for {0}: '.format(args.gmp_username))

    global gmp

    # return an Etree at successful responses and raise execption on
    # unsuccessful ones
    gmp = Gmp(connection, transform=EtreeCheckCommandTransform())

    try:
        gmp.authenticate(args.gmp_username, args.gmp_password)
    except Exception as e: # pylint: disable=broad-except
        print('Please check your credentials!')
        print(e)
        sys.exit(1)

    with_script = args.script and len(args.script) > 0
    no_script_no_interactive = not args.interactive and not with_script
    script_and_interactive = args.interactive and with_script
    only_interactive = not with_script and args.interactive
    only_script = not args.interactive and with_script

    if no_script_no_interactive:
        enter_interactive_mode()

    if only_interactive:
        enter_interactive_mode()

    if script_and_interactive:
        load(args.script[0])
        enter_interactive_mode()

    if only_script:
        load(args.script[0])

    gmp.disconnect()


def enter_interactive_mode():
    code.interact(
        banner='GVM Interactive Console. Type "help" to get information \
about functionality.',
        local=dict(globals(), **locals()))


def pretty(xml):
    """Prints beautiful XML-Code

    This function gets an object of list<lxml.etree._Element>
    or directly a lxml element.
    Print it with good readable format.

    Arguments:
        xml {obj} -- list<lxml.etree._Element> or directly a lxml element
    """
    if isinstance(xml, list):
        for item in xml:
            if etree.iselement(item):
                print(etree.tostring(item, pretty_print=True).decode('utf-8'))
            else:
                print(item)
    elif etree.iselement(xml):
        print(etree.tostring(xml, pretty_print=True).decode('utf-8'))


def load(path):
    """Loads a file into the interactive console

    Loads a file into the interactive console and execute it.
    TODO: Needs some security checks.

    Arguments:
        path {str} -- Path of file
    """
    try:
        file = open(path, 'r', newline='').read()
        exec(file, globals())
    except OSError as e:
        print(str(e))


if __name__ == '__main__':
    main()
