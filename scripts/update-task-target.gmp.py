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
import time

from argparse import Namespace
from gvm.protocols.gmp import Gmp

from gvmtools.helper import error_and_exit


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script will update target hosts information for a desired task.
        Two parameters after the script name are required.

        1. <hosts_file>  -- .csv file containing desired target hosts separated by ','
        2. <task_uuid>   -- uuid of task to be modified

        Example for starting up the routine:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/update-task-target.gmp.py hosts_file.csv \
    "303fa0a6-aa9b-43c4-bac0-66ae0b2d1698"

        """
        print(message)
        sys.exit()


def load_host_file(filename):
    host_list = list()

    try:
        f = open(filename)
        for line in f:
            host = line.split(",")[0]
            host = host.strip()
            if len(host) == 0:
                continue
            host_list.append(host)

    except IOError as e:
        error_and_exit("Failed to read host_file: {} (exit)".format(str(e)))

    if len(host_list) == 0:
        error_and_exit("Host file is empty (exit)")

    hosts_string = ', '.join(map(str, host_list))

    return hosts_string


def copy_send_target(gmp, hosts_file, old_target_id):
    hosts_string = load_host_file(hosts_file)
    keywords = {'hosts': hosts_string}

    keywords['comment'] = 'This target was automatically modified: {}'.format(
        time.strftime("%Y/%m/%d-%H:%M:%S")
    )

    old_target = gmp.get_target(target_id=old_target_id)[0]

    objects = ('reverse_lookup_only', 'reverse_lookup_unify', 'name')
    for obj in objects:
        var = old_target.xpath('{}/text()'.format(obj))[0]
        if var == '0':
            var = ''
        keywords['{}'.format(obj)] = var

    port_list = {}
    port_list = old_target.xpath('port_list/@id')[0]
    keywords['port_list_id'] = port_list

    keywords['name'] += "_copy"  # the name must differ from existing names

    new_target_id = gmp.create_target(**keywords).xpath('@id')[0]

    print('\n  New target created!\n')
    print('Target_id:   {}'.format(new_target_id))
    print('Target_name: {}\n'.format(keywords['name']))

    return new_target_id


def create_target_hosts(gmp, host_file, task_id, old_target_id):
    new_target_id = copy_send_target(gmp, host_file, old_target_id)

    gmp.modify_task(task_id=task_id, target_id=new_target_id)

    print('  Task successfully modified!\n')


def check_to_delete(gmp, target_id):
    target = gmp.get_target(target_id=target_id)[0]
    if '0' in target.xpath("in_use/text()"):
        gmp.delete_target(target_id=target_id)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    hosts_file = args.script[1]
    task_id = args.script[2]

    task = gmp.get_task(task_id=task_id)[1]
    old_target_id = task.xpath('target/@id')[0]

    create_target_hosts(gmp, hosts_file, task_id, old_target_id)
    check_to_delete(gmp, old_target_id)


if __name__ == '__gmp__':
    main(gmp, args)
