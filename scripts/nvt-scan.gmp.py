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
from datetime import datetime
from argparse import Namespace
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script creates a new task with specific host and nvt!
        It needs two parameters after the script name.

        <oid>       -- oid of the nvt
        <target>    -- scan target

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> 1.3.6.1.4.1.25623.1.0.106223 localhost
        """
        print(message)
        sys.exit()


def create_scan_config(gmp, nvt_oid) -> str:
    # Create new config
    copy_id = '085569ce-73ed-11df-83c3-002264764cea'
    config_name = nvt_oid
    config_id = ''

    try:
        res = gmp.create_scan_config(copy_id, config_name)
        config_id = res.xpath('@id')[0]

        # Modify the config with an nvt oid
        nvt = gmp.get_scan_config_nvt(nvt_oid)
        family = nvt.xpath('nvt/family/text()')[0]

        gmp.modify_scan_config_set_nvt_selection(
            config_id=config_id, nvt_oids=[nvt_oid], family=family
        )

        # This nvts must be present to work
        family = 'Port scanners'
        nvts = ['1.3.6.1.4.1.25623.1.0.14259', '1.3.6.1.4.1.25623.1.0.100315']
        gmp.modify_scan_config_set_nvt_selection(
            config_id, nvt_oids=nvts, family=family
        )

    except GvmError:
        res = gmp.get_scan_configs(filter_string=f'name={config_name}')
        config_id = res.xpath('config/@id')[0]

    return config_id


def create_target(gmp: Gmp, name: str) -> str:
    try:
        res = gmp.create_target(name, hosts=[name])
        target_id = res.xpath('@id')[0]
    except GvmError:
        res = gmp.get_targets(filter_string=f'name={name} hosts={name}')
        target_id = res.xpath('target/@id')[0]

    return target_id


def create_and_start_task(
    gmp: Gmp, name: str, nvt_oid: str, config_id: str, target_id: str
) -> None:
    # Standard Scanner OpenVAS Default
    scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Create task
    task_name = f'{name}_{nvt_oid}_{date_time}'
    res = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    task_id = res.xpath('@id')[0]

    # Start the task
    gmp.start_task(task_id=task_id)
    print(f'\nTask {task_id} started')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    nvt_oid = args.script[1]
    target_name = args.script[2]

    config_id = create_scan_config(gmp, nvt_oid)
    target_id = create_target(gmp, target_name)

    create_and_start_task(gmp, target_name, nvt_oid, config_id, target_id)


if __name__ == '__gmp__':
    main(gmp, args)
