# -*- coding: utf-8 -*-
# Copyright (C) 2020 Greenbone Networks GmbH
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
import sys

from pathlib import Path

from gvm.version import (
    print_version,
    get_version_from_pyproject_toml,
    is_version_pep440_compliant,
    strip_version,
    safe_version,
    update_pyproject_version,
    update_version_file,
    versions_equal,
)

from gvmtools import get_version


def _update_gvm_tools_version(
    new_version: str, pyproject_toml_path: Path, *, force: bool = False
):
    if not pyproject_toml_path.exists():
        sys.exit(
            'Could not find pyproject.toml file in the current working dir.'
        )

    cwd_path = Path.cwd()
    pyproject_version = get_version_from_pyproject_toml(
        pyproject_toml_path=pyproject_toml_path
    )
    version_file_path = cwd_path / 'gvmtools' / '__version__.py'

    if not version_file_path.exists():
        version_file_path.touch()
    elif not force and versions_equal(new_version, get_version()):
        print('Version is already up-to-date.')
        sys.exit(0)

    update_pyproject_version(
        new_version=new_version, pyproject_toml_path=pyproject_toml_path
    )

    update_version_file(
        new_version=new_version, version_file_path=version_file_path,
    )

    print(
        'Updated version from {} to {}'.format(
            pyproject_version, safe_version(new_version)
        )
    )


def _verify_version(version: str, pyproject_toml_path: Path) -> None:
    gvmtools_version = get_version()
    pyproject_version = get_version_from_pyproject_toml(
        pyproject_toml_path=pyproject_toml_path
    )
    if not is_version_pep440_compliant(gvmtools_version):
        sys.exit(
            "The version in gvmtools/__version__.py is not PEP 440 compliant."
        )

    if pyproject_version != gvmtools_version:
        sys.exit(
            "The version set in the pyproject.toml file \"{}\" doesn't "
            "match the gvm-tools version \"{}\"".format(
                pyproject_version, gvmtools_version
            )
        )

    if version != 'current':
        provided_version = strip_version(version)
        if provided_version != gvmtools_version:
            sys.exit(
                "Provided version \"{}\" does not match the python-gvm "
                "version \"{}\"".format(provided_version, gvmtools_version)
            )

    print('OK')


def main():
    parser = argparse.ArgumentParser(
        description='Version handling utilities for gvm-tools.', prog='version'
    )

    subparsers = parser.add_subparsers(
        title='subcommands',
        description='valid subcommands',
        help='additional help',
        dest='command',
    )

    verify_parser = subparsers.add_parser('verify')
    verify_parser.add_argument('version', help='version string to compare')

    subparsers.add_parser('show')

    update_parser = subparsers.add_parser('update')
    update_parser.add_argument('version', help='version string to use')
    update_parser.add_argument(
        '--force',
        help="don't check if version is already set",
        action="store_true",
    )

    args = parser.parse_args()

    if not getattr(args, 'command', None):
        parser.print_usage()
        sys.exit(0)

    pyproject_toml_path = Path.cwd() / 'pyproject.toml'

    if args.command == 'update':
        _update_gvm_tools_version(
            args.version,
            pyproject_toml_path=pyproject_toml_path,
            force=args.force,
        )
    elif args.command == 'show':
        print_version(pyproject_toml_path=pyproject_toml_path)
    elif args.command == 'verify':
        _verify_version(args.version, pyproject_toml_path=pyproject_toml_path)


if __name__ == '__main__':
    main()
