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
from argparse import Namespace
from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script creates a new task with specific host and nvt!
        It needs two parameters after the script name.
        First one is the oid of the nvt and the second one is the
        chosen scan target.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/start-nvt-scan.gmp.py \
    1.3.6.1.4.1.25623.1.0.106223 localhost
        """
        print(message)
        sys.exit()


def get_scan_config(gmp, nvt_oid):
    # Choose from existing config, which to copy or create new config
    res = gmp.get_scan_configs()

    config_ids = res.xpath('config/@id')

    for i, conf in enumerate(res.xpath('config')):
        config_id = conf.xpath('@id')[0]
        name = conf.xpath('name/text()')[0]
        print('\n({0}) {1}: ({2})'.format(i, name, config_id))

    while True:
        chosen_config = input(
            '\nChoose your config or create new one[0-{len} | n]: '.format(
                len=len(config_ids) - 1
            )
        )

        if chosen_config == 'n':
            chosen_copy_config = int(
                input(
                    'Which config to copy? [0-{len}]: '.format(
                        len=len(config_ids) - 1
                    )
                )
            )
            config_name = input('Enter new Name for config: ')

            copy_id = config_ids[chosen_copy_config]

            res = gmp.clone_scan_config(copy_id)

            config_id = res.xpath('@id')[0]

            # Modify the config with an nvt oid
            if len(nvt_oid) == 0:
                nvt_oid = input('NVT OID: ')

            nvt = gmp.get_scan_config_nvt(nvt_oid=nvt_oid)
            family = nvt.xpath('nvt/family/text()')[0]

            gmp.modify_scan_config(
                config_id,
                'nvt_selection',
                name=config_name,
                nvt_oids=[nvt_oid],
                family=family,
            )

            # This nvts must be present to work
            family = 'Port scanners'
            nvts = [
                '1.3.6.1.4.1.25623.1.0.14259',
                '1.3.6.1.4.1.25623.1.0.100315',
            ]

            gmp.modify_scan_config(
                config_id, 'nvt_selection', nvt_oids=nvts, family=family
            )
            return config_id

        if 0 <= int(chosen_config) < len(config_ids):
            return config_ids[int(chosen_config)]


def get_target(gmp, hosts):
    # create a new target or use an existing
    targets = gmp.get_targets()
    target_ids = targets.xpath('target/@id')

    for i, target in enumerate(targets.xpath('target')):
        name = target.xpath('name/text()')[0]
        print('\n({0}) {1}'.format(i, name))

    while True:
        if target_ids:
            chosen_target = input(
                '\nChoose your target or create new one[0-{len} | n]: '.format(
                    len=len(target_ids) - 1
                )
            )
        else:
            chosen_target = 'n'

        if chosen_target == 'n':
            if len(hosts) == 0:
                hosts = input('Target hosts (comma separated): ')

            name = input('Name of target: ')

            res = gmp.create_target(name, hosts=hosts.split(','))
            return res.xpath('@id')[0]

        if 0 <= int(chosen_target) < len(target_ids):
            return target_ids[int(chosen_target)]


def get_scanner(gmp):
    res = gmp.get_scanners()
    scanner_ids = res.xpath('scanner/@id')

    for i, scanner in enumerate(res.xpath('scanner')):
        scanner_id = scanner.xpath('@id')[0]
        name = scanner.xpath('name/text()')[0]
        # configs[id] = name
        print("\n({0})\n{1}: ({2})".format(i, name, scanner_id))

    while True:
        chosen_scanner = int(
            input(
                '\nChoose your scanner [0-{len}]: '.format(
                    len=len(scanner_ids) - 1
                )
            )
        )
        if 0 <= chosen_scanner < len(scanner_ids):
            return scanner_ids[chosen_scanner]


def create_and_start_task(
    gmp, task_name, task_comment, config_id, target_id, scanner_id
):
    res = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
        comment=task_comment,
    )

    # Start the task
    task_id = res.xpath('@id')[0]
    gmp.start_task(task_id)
    print('Task started')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    nvt_oid = args.script[1]
    hosts = args.script[2]

    task_name = input('Task name: ')
    task_comment = input('Task comment: ')

    config_id = get_scan_config(gmp, nvt_oid)
    target_id = get_target(gmp, hosts)
    scanner_id = get_scanner(gmp)

    create_and_start_task(
        gmp, task_name, task_comment, config_id, target_id, scanner_id
    )


if __name__ == '__gmp__':
    main(gmp, args)
