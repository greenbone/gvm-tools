# -*- coding: utf-8 -*-
# Copyright (C) 2018 inovex GmbH
# Copyright (C) 2019-2021 Greenbone Networks GmbH
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
from typing import List
from argparse import Namespace
from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    message = """
        This script makes an alert scan
        It needs two parameters after the script name.

        1. <sender_email>     -- E-Mail of the sender
        2. <receiver_email>   -- E-Mail of the receiver
        
                Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/start-multiple-alert-scan.gmp.py <sender_email> <receiver_email>
    """
    if len_args != 2:
        print(message)
        sys.exit()


# returns a list containing all port_list names
def get_port_list_names(gmp) -> List[str]:
    res = gmp.get_port_lists()
    port_names_list = [""]
    for name in res.findall("port_list/name"):
        port_names_list.append(str(name.text))
    return port_names_list


def get_scan_config(gmp, debug=False):
    # get all configs of the openvas instance
    res = gmp.get_scan_configs()

    # configurable template
    template = "fast"

    # match the config abbreviation to accepted config names
    config_list = [
        'Full and fast',
        'Full and fast ultimate',
        'Full and very deep',
        'Full and very deep ultimate',
        'System Discovery',
    ]
    template_abbreviation_mapper = {
        "fast": config_list[0],
        "fast-ulti": config_list[1],
        "deep": config_list[2],
        "deep-ulti": config_list[3],
        "discovery": config_list[4],
    }
    config_id = "-"
    for conf in res.xpath('config'):
        cid = conf.xpath('@id')[0]
        name = conf.xpath('name/text()')[0]

        # get the config id of the desired template
        if template_abbreviation_mapper.get(template, "-") == name:
            config_id = cid
            if debug:
                print("%s: %s" % (name, config_id))
            break
    # check for existence of the desired config
    if config_id == "-":
        print(
            "error: could not recognize template '%s'\n"
            "valid template names are: %s\n" % (template, config_list)
        )
        exit()

    return config_id


def get_target(gmp, debug=False):
    # find a targetName
    targets = gmp.get_targets()

    counter = 0
    exists = True

    # iterate over existing targets and find a vacant targetName
    while exists:
        exists = False
        target_name = "targetName%s" % str(counter)
        for target in targets.xpath('target'):
            name = target.xpath('name/text()')[0]
            if name == target_name:
                exists = True
                break
        counter += 1

    if debug:
        print("target name: %s" % target_name)

    # iterate over existing port lists and find a vacant name
    new_port_list_name = "portlistName"
    counter = 0

    while True:
        portlist_name = '%s%s' % (new_port_list_name, str(counter))
        if portlist_name not in get_port_list_names(gmp):
            break
        counter += 1

    # configurable port string
    port_string = "T:80-80"
    # create port list
    portlist = gmp.create_port_list(portlist_name, port_string)
    portlist_id = portlist.xpath('@id')[0]
    if debug:
        print("Portlist-name:\t%s" % str(portlist_name))
        print("Portlist-id:\t%s" % str(portlist_id))

    # configurable hosts
    hosts = ["localhost"]

    # integrate port list id into create_target
    res = gmp.create_target(
        name=target_name, hosts=hosts, port_list_id=portlist_id
    )
    return res.xpath('@id')[0]


def get_alerts(gmp, sender_email, recipient_email, debug=False) -> List[str]:
    # configurable alert name
    alert_name = recipient_email

    # create alert if necessary
    alert_object = gmp.get_alerts(filter=f'name={alert_name}')
    alert_id = None
    alert = alert_object.xpath('alert')
    if len(alert) == 0:
        gmp.create_alert(
            alert_name,
            event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={'status': 'Done'},
            condition=gmp.types.AlertCondition.ALWAYS,
            method=gmp.types.AlertMethod.EMAIL,
            method_data={
                """Task '$n': $e

After the event $e,
the following condition was met: $c

This email escalation is configured to attach report format '$r'.
Full details and other report formats are available on the scan engine.

$t

Note:
This email was sent to you as a configured security scan escalation.
Please contact your local system administrator if you think you
should not have received it.
""": "message",
                "2": "notice",
                sender_email: "from_address",
                "[OpenVAS-Manager] Task": "subject",
                "c402cc3e-b531-11e1-9163-406186ea4fc5": "notice_attach_format",
                recipient_email: "to_address",
            },
        )
        alert_object = gmp.get_alerts(filter=f'name={recipient_email}')
        alert = alert_object.xpath('alert')
        alert_id = alert[0].get('id', 'no id found')
    else:
        alert_id = alert[0].get('id', 'no id found')
        if debug:
            print(f"alert_id: {str(alert_id)}")

    # second configurable alert name
    alert_name2 = f"{recipient_email}-2"

    # create second alert if necessary
    alert_object2 = gmp.get_alerts(filter=f'name={alert_name2}')
    alert_id2 = None
    alert2 = alert_object2.xpath('alert')
    if len(alert2) == 0:
        gmp.create_alert(
            alert_name2,
            event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={'status': 'Done'},
            condition=gmp.types.AlertCondition.ALWAYS,
            method=gmp.types.AlertMethod.EMAIL,
            method_data={
                """Task '$n': $e

After the event $e,
the following condition was met: $c

This email escalation is configured to attach report format '$r'.
Full details and other report formats are available on the scan engine.

$t

Note:
This email was sent to you as a configured security scan escalation.
Please contact your local system administrator if you think you
should not have received it.
""": "message",
                "2": "notice",
                sender_email: "from_address",
                "[OpenVAS-Manager] Task": "subject",
                recipient_email: "to_address",
            },
        )
        alert_object2 = gmp.get_alerts(filter=f'name={recipient_email}')
        alert2 = alert_object2.xpath('alert')
        alert_id2 = alert2[0].get('id', 'no id found')
    else:
        alert_id2 = alert2[0].get('id', 'no id found')
        if debug:
            print(f"alert_id2: {str(alert_id2)}")

    return [alert_id, alert_id2]


def get_scanner(gmp):
    res = gmp.get_scanners()
    scanner_ids = res.xpath('scanner/@id')
    return scanner_ids[1]  # default scanner


def create_and_start_task(
    gmp, config_id, target_id, scanner_id, alerts, debug=False
):
    # Create the task
    tasks = gmp.get_tasks(filter="name~ScanDoneMultipleAlert")
    task_name = f"ScanDoneMultipleAlert{len(tasks.xpath('tasks/@id'))}"
    task_comment = "test comment"
    res = gmp.create_task(
        name=task_name,
        config_id=config_id,
        target_id=target_id,
        scanner_id=scanner_id,
        alert_ids=alerts,
        comment=task_comment,
    )
    # Start the task
    task_id = res.xpath('@id')[0]
    gmp.start_task(task_id)

    print('Task started: %s' % task_name)

    if debug:
        # Stop the task (for performance reasons)
        gmp.stop_task(task_id)
        print('Task stopped')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    sender_email = args.script[1]
    recipient_email = args.script[2]

    config_id = get_scan_config(gmp)
    target_id = get_target(gmp)
    alerts = get_alerts(gmp, sender_email, recipient_email)
    scanner_id = get_scanner(gmp)

    create_and_start_task(gmp, config_id, target_id, scanner_id, alerts)

    print("\nScript finished\n")


if __name__ == '__gmp__':
    main(gmp, args)
