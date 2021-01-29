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

import code
import logging
import os
import sys

from argparse import Namespace

from gvm import get_version as get_gvm_version
from gvm.xml import pretty_print
from gvm.protocols.gmp import Gmp
from gvm.protocols.latest import Osp
from gvm.transforms import EtreeCheckCommandTransform

from gvmtools import get_version
from gvmtools.helper import authenticate, run_script, do_not_run_as_root
from gvmtools.parser import (
    create_parser,
    create_connection,
    PROTOCOL_OSP,
    PROTOCOL_GMP,
)

__version__ = get_version()
__api_version__ = get_gvm_version()

logger = logging.getLogger(__name__)

HELP_TEXT = """
    Command line tool to access services via GMP (Greenbone Management
    Protocol) and OSP (Open Scanner Protocol)

    gvm-pyshell provides an interactive shell for GMP and OSP services.

    Example:
        >>> tasks = gmp.get_tasks()
        >>> task_names = tasks.xpath('task/name/text()')
        >>> print(task_names)
        ['Scan Task']
        >>> pretty_print('<xml/>')
        <xml/>

    The interactive shell can be exited with:
        Ctrl + D on Linux  or
        Ctrl + Z on Windows

    The protocol specifications for GMP and OSP are available at:
      https://docs.greenbone.net/index.html#api_documentation"""


class Help(object):
    """Help class to overwrite the help function from python itself."""

    def __call__(self):
        return print(HELP_TEXT)

    def __repr__(self):
        # do pwd command
        return HELP_TEXT


def main():
    do_not_run_as_root()

    parser = create_parser(description=HELP_TEXT, logfilename='gvm-pyshell.log')

    parser.add_protocol_argument()

    parser.add_argument(
        '-i',
        '--interactive',
        action='store_true',
        default=False,
        help='Start an interactive Python shell',
    )

    parser.add_argument(
        'scriptname',
        nargs='?',
        metavar="SCRIPT",
        help='Path to script to be preloaded (example: myscript.gmp.py)',
    )
    parser.add_argument(
        'scriptargs',
        nargs='*',
        metavar="ARG",
        help='Arguments for preloaded script',
    )

    args = parser.parse_args()

    connection = create_connection(**vars(args))

    transform = EtreeCheckCommandTransform()

    global_vars = {
        'help': Help(),
        'pretty_print': pretty_print,
        '__version__': __version__,
        '__api_version__': __api_version__,
    }

    username = None
    password = None

    if args.protocol == PROTOCOL_OSP:
        protocol_class = Osp
        name = 'osp'
    else:
        protocol_class = Gmp
        name = 'gmp'

    with protocol_class(connection, transform=transform) as protocol:
        global_vars[name] = protocol
        global_vars['__name__'] = '__{}__'.format(name)

        if args.protocol == PROTOCOL_GMP:
            if args.gmp_username:
                (username, password) = authenticate(
                    protocol,
                    username=args.gmp_username,
                    password=args.gmp_password,
                )

        shell_args = Namespace(username=username, password=password)

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
            if only_script:
                print(
                    'Using gvm-pyshell for running scripts only is deprecated. '
                    'Please use gvm-script instead',
                    file=sys.stderr,
                )

            script_name = args.scriptname
            run_script(script_name, global_vars)

            if not only_script:
                enter_interactive_mode(global_vars)


def enter_interactive_mode(global_vars):
    code.interact(
        banner='GVM Interactive Console {} API {}. Type "help" to get '
        'information about functionality.'.format(__version__, __api_version__),
        local=dict(global_vars),
    )


if __name__ == '__main__':
    main()
