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


def clean_sensor(gmp):
    tasks = gmp.get_tasks(
        filter="rows=-1 not status=Running and "
        "not status=Requested and not "
        "status=&quot;Stop Requested&quot;"
    )

    for tid in tasks.xpath('task/@id'):
        print('Removing task %s ... ' % tid)
        status_text = gmp.delete_task(tid, ultimate=True).xpath('@status_text')[
            0
        ]
        print(status_text)

    targets = gmp.get_targets(filter="rows=-1 not _owner=&quot;&quot;")
    for tid in targets.xpath('target/@id'):
        print('Removing target %s ... ' % tid)
        status_text = gmp.delete_target(tid, ultimate=True).xpath(
            '@status_text'
        )[0]
        print(status_text)

    configs = gmp.get_configs(filter="rows=-1 not _owner=&quot;&quot;")
    for cid in configs.xpath('config/@id'):
        print('Removing config %s ... ' % cid)
        status_text = gmp.delete_config(cid, ultimate=True).xpath(
            '@status_text'
        )[0]
        print(status_text)

    port_lists = gmp.get_port_lists(filter="rows=-1 not _owner=&quot;&quot;")
    for pid in port_lists.xpath('port_list/@id'):
        print('Removing port_list %s ... ' % pid)
        status_text = gmp.delete_port_list(pid, ultimate=True).xpath(
            '@status_text'
        )[0]
        print(status_text)

    credentials = gmp.get_credentials(filter="rows=-1 not _owner=&quot;&quot;")
    for cid in credentials.xpath('credential/@id'):
        print('Removing credential %s ... ' % cid)
        status_text = gmp.delete_credential(cid, ultimate=True).xpath(
            '@status_text'
        )[0]
        print(status_text)

    print('Emptying trash... ')
    status_text = gmp.empty_trashcan().xpath('@status_text')[0]
    print(status_text)


def main(gmp, args):
    # pylint: disable=unused-argument

    message = """
    This script removes all resources from a sensor, except active tasks.

    """
    print(message)

    clean_sensor(gmp)


if __name__ == '__gmp__':
    main(gmp, args)
