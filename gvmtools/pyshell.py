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
import logging
import os
import sys

from gvm import get_version as get_gvm_version
from gvm.connections import (SSHConnection,
                             TLSConnection,
                             UnixSocketConnection,
                             DEFAULT_UNIX_SOCKET_PATH,
                             DEFAULT_TIMEOUT,
                             DEFAULT_GVM_PORT)
from gvm.protocols.latest import Gmp, Osp
from gvm.transforms import EtreeCheckCommandTransform

from gvmtools import get_version
from gvmtools.helper import authenticate

__version__ = get_version()
__api_version__ = get_gvm_version()

logger = logging.getLogger(__name__)

PROTOCOL_OSP = 'OSP'
PROTOCOL_GMP = 'GMP'
DEFAULT_PROTOCOL = PROTOCOL_GMP

HELP_TEXT = """
    Command line tool to access services via GMP (Greenbone Management
    Protocol) and OSP (Open Scanner Protocol)

    gvm-pyshell provides an interactive shell for GMP and OSP services
    and can be used to execute custom OSP/GMP scripts.

    Example:
        >>> tasks = gmp.get_tasks()
        >>> task_names = tasks.xpath('task/name/text()')
        >>> print(task_names)
        ['Scan Task']

    The interactive shell can be exit with:
        Ctrl + D on Linux  or
        Ctrl + Z on Windows

    The protocol specifications for GMP and OSP are available at:
      https://docs.greenbone.net/index.html#api_documentation"""


class Help(object):
    """Help class to overwrite the help function from python itself.
    """

    def __call__(self):
        return print(HELP_TEXT)

    def __repr__(self):
        # do pwd command
        return HELP_TEXT


class Arguments:

    def __init__(self, **kwargs):
        self._args = kwargs

    def get(self, key):
        return self._args[key]

    def __getattr__(self, key):
        return self.get(key)

    def __setattr__(self, name, value):
        if name.startswith('_'):
            super().__setattr__(name, value)
        else:
            self._args[name] = value

    def __getitem__(self, key):
        return self.get(key)

    def __repr__(self):
        return repr(self._args)


def main():
    parser = argparse.ArgumentParser(
        prog='gvm-pyshell',
        description=HELP_TEXT,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False)

    subparsers = parser.add_subparsers(metavar='[connection_type]')
    subparsers.required = True
    subparsers.dest = 'connection_type'

    parser.add_argument(
        '-h', '--help', action='help',
        help='Show this help message and exit')

    parent_parser = argparse.ArgumentParser(add_help=False)

    parent_parser.add_argument(
        '-c', '--config', nargs='?', const='~/.config/gvm-tools.conf',
        help='Configuration file path (default: ~/.config/gvm-tools.conf)')
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
        except Exception as e: # pylint: disable=broad-except
            print(str(e), file=sys.stderr)

    parent_parser.set_defaults(**defaults)

    parent_parser.add_argument(
        '--timeout', required=False, default=DEFAULT_TIMEOUT, type=int,
        help='Response timeout in seconds, or -1 to wait '
             'indefinitely (default: %(default)s)')
    parent_parser.add_argument(
        '--log', nargs='?', dest='loglevel', const='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Activate logging (default level: %(default)s)')
    parent_parser.add_argument(
        '-i', '--interactive', action='store_true', default=False,
        help='Start an interactive Python shell')
    parent_parser.add_argument(
        '--protocol', required=False, default=DEFAULT_PROTOCOL,
        choices=[PROTOCOL_GMP, PROTOCOL_OSP],
        help='Service protocol to use (default: %(default)s)')
    parent_parser.add_argument('--gmp-username', help='Username for GMP service')
    parent_parser.add_argument('--gmp-password', help='Password for GMP service')
    parent_parser.add_argument(
        'scriptname', nargs='?', metavar="SCRIPT",
        help='Path to script to be preloaded (example: myscript.gmp)')
    parent_parser.add_argument(
        'scriptargs', nargs='*', metavar="ARG",
        help='Arguments for preloaded script')

    parser_ssh = subparsers.add_parser(
        'ssh', help='Use SSH to connect to service',
        parents=[parent_parser])
    parser_ssh.add_argument('--hostname', required=True,
                            help='Hostname or IP address')
    parser_ssh.add_argument('--port', required=False,
                            default=22, help='SSH port (default: %(default)s)')
    parser_ssh.add_argument('--ssh-user', default='gmp',
                            help='SSH username (default: %(default)s)')

    parser_tls = subparsers.add_parser(
        'tls', help='Use TLS secured connection to connect to service',
        parents=[parent_parser])
    parser_tls.add_argument('--hostname', required=True,
                            help='Hostname or IP address')
    parser_tls.add_argument('--port', required=False,
                            default=DEFAULT_GVM_PORT,
                            help='GMP/OSP port (default: %(default)s)')
    parser_tls.add_argument('--certfile', required=False, default=None,
                            help='Path to the certificate file for client authentication')
    parser_tls.add_argument('--keyfile', required=False, default=None,
                            help='Path to key file for client authentication')
    parser_tls.add_argument('--cafile', required=False, default=None,
                            help='Path to CA certificate for server authentication')
    parser_tls.add_argument('--no-credentials', required=False, default=False,
                            help='Use only certificates for authentication')

    parser_socket = subparsers.add_parser(
        'socket', help='Use UNIX Domain socket to connect to service',
        parents=[parent_parser])
    parser_socket.add_argument(
        '--sockpath', nargs='?', default=None,
        help='Deprecated, use --socketpath instead')
    parser_socket.add_argument(
        '--socketpath', nargs='?', default=DEFAULT_UNIX_SOCKET_PATH,
        help='Path to UNIX Domain socket (default: %(default)s)')

    parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {version} (API version {apiversion})'.format(
            version=__version__, apiversion=__api_version__),
        help='Show version information and exit')

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
            password=''
        )

    transform = EtreeCheckCommandTransform()

    global_vars = {
        'help': Help(),
        '__version__': __version__,
        '__api_version__': __api_version__,
    }

    username = None
    password = None

    if args.protocol == PROTOCOL_OSP:
        protocol = Osp(connection, transform=transform)
        global_vars['osp'] = protocol
        global_vars['__name__'] = '__osp__'
    else:
        protocol = Gmp(connection, transform=transform)
        global_vars['gmp'] = protocol
        global_vars['__name__'] = '__gmp__'

        if args.gmp_username:
            (username, password) = authenticate(
                protocol, username=args.gmp_username,
                password=args.gmp_password)

    shell_args = Arguments(
        username=username, password=password)

    global_vars['args'] = shell_args

    with_script = args.scriptname and len(args.scriptname) > 0

    if with_script:
        argv = [os.path.abspath(args.scriptname), *args.scriptargs]
        shell_args.argv = argv
        # for backwards compatibility we add script here
        shell_args.script = argv

    no_script_no_interactive = not args.interactive and not with_script
    script_and_interactive = args.interactive and with_script
    only_interactive = not with_script and args.interactive
    only_script = not args.interactive and with_script

    if only_interactive or no_script_no_interactive:
        enter_interactive_mode(global_vars)

    if script_and_interactive or only_script:
        script_name = args.scriptname
        load(script_name, global_vars)

    if not only_script:
        enter_interactive_mode(global_vars)

    protocol.disconnect()


def enter_interactive_mode(global_vars):
    code.interact(
        banner='GVM Interactive Console. Type "help" to get information \
about functionality.',
        local=dict(global_vars))


def load(path, global_vars):
    """Loads a file into the interactive console

    Loads a file into the interactive console and execute it.
    TODO: Needs some security checks.

    Arguments:
        path {str} -- Path of file
    """
    try:
        file = open(path, 'r', newline='').read()

        exec(file, global_vars) # pylint: disable=exec-used
    except OSError as e:
        print(str(e))


if __name__ == '__main__':
    main()
