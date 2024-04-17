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

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvm.errors import GvmResponseError


def clean_sensor(gmp: Gmp) -> None:
    tasks = gmp.get_tasks(
        filter_string="rows=-1 not status=Running and "
        "not status=Requested and not "
        "status=&quot;Stop Requested&quot;"
    )

    try:
        for task_id in tasks.xpath("task/@id"):
            print(f"Removing task {task_id} ... ")
            status_text = gmp.delete_task(task_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    targets = gmp.get_targets(filter_string="rows=-1 not _owner=&quot;&quot;")
    try:
        for target_id in targets.xpath("target/@id"):
            print(f"Removing target {target_id} ... ")
            status_text = gmp.delete_target(target_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    configs = gmp.get_scan_configs(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for config_id in configs.xpath("config/@id"):
            print(f"Removing config {config_id} ... ")
            status_text = gmp.delete_scan_config(config_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    port_lists = gmp.get_port_lists(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for port_list_id in port_lists.xpath("port_list/@id"):
            print(f"Removing port_list {port_list_id} ... ")
            status_text = gmp.delete_port_list(port_list_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    alerts = gmp.get_alerts(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for alert_id in alerts.xpath("alert/@id"):
            print(f"Removing alert {alert_id} ... ")
            status_text = gmp.delete_alert(alert_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    schedules = gmp.get_schedules(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for schedule_id in schedules.xpath("schedule/@id"):
            print(f"Removing schedule {schedule_id} ... ")
            status_text = gmp.delete_schedule(schedule_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    tags = gmp.get_tags(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for tag_id in tags.xpath("tag/@id"):
            print(f"Removing tag {tag_id} ... ")
            status_text = gmp.delete_tag(tag_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    filters = gmp.get_filters(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for filter_id in filters.xpath("filter/@id"):
            print(f"Removing filter {filter_id} ... ")
            status_text = gmp.delete_filter(filter_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    credentials = gmp.get_credentials(
        filter_string="rows=-1 not _owner=&quot;&quot;"
    )
    try:
        for config_id in credentials.xpath("credential/@id"):
            print(f"Removing credential {config_id} ... ")
            status_text = gmp.delete_credential(config_id, ultimate=True).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

    print("Emptying trash... ")
    try:
        status_text = gmp.empty_trashcan().xpath("@status_text")[0]
        print(status_text)
    except GvmResponseError as gvmerr:
        print(f"{gvmerr=}")
        pass 

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    print(
        "This script removes all resources from a sensor, except active tasks.\n"
    )

    clean_sensor(gmp)


if __name__ == "__gmp__":
    main(gmp, args)
