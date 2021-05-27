# -*- coding: utf-8 -*-
# Copyright (C) 2017-2021 Greenbone Networks GmbH
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

import sys
from random import choice
from argparse import Namespace
from gvm.protocols.gmp import Gmp

from gvmtools.helper import generate_id


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script will create random data in the given GVM database

        1. <count>  -- Number of datasets to create

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/create-dummy-data.gmp.py <count>
        """
        print(message)
        sys.exit()


def create_data(gmp, count):
    config_ids = []
    target_ids = []

    for _ in range(0, count):
        name = generate_id()
        gmp.create_credential(
            name,
            login=name,
            password=name,
            credential_type=gmp.types.CredentialType.PASSWORD_ONLY,
        )
    print(str(count) + ' random credentials generated.')

    for _ in range(0, count):
        name = generate_id()
        gmp.create_port_list(name, port_range='T:1-42')
    print(str(count) + ' random port lists generated.')

    for _ in range(0, count):
        name = generate_id()
        res = gmp.create_scan_config(
            '085569ce-73ed-11df-83c3-002264764cea', name
        )
        config_ids.append(res.xpath('@id')[0])
    print(str(count) + ' random scan configs generated.')

    for _ in range(0, count):
        name = generate_id()
        res = gmp.create_target(name, hosts=['127.0.0.1'])

        target_ids.append(res.xpath('@id')[0])
    print(str(count) + ' random targets generated.')

    for _ in range(0, count):
        name = generate_id()
        config_id = choice(config_ids)
        target_id = choice(target_ids)
        gmp.create_task(
            name, config_id, target_id, '08b69003-5fc2-4037-a479-93b440211c73'
        )
    print(str(count) + ' random tasks generated.')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    create_data(gmp, int(args.script[1]))


if __name__ == '__gmp__':
    main(gmp, args)
