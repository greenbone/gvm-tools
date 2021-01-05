# -*- coding: utf-8 -*-
# Copyright (C) 2018 Henning Häcker
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

from typing import List
from argparse import ArgumentParser, RawTextHelpFormatter


HELP_TEXT = """
        This script makes an E-Mail alert scan.

        Usage examples: 
            $ gvm-script --gmp-username name --gmp-password pass ssh --hostname
            ... start-alert-scan.gmp.py +h
            ... start-alert-scan.gmp.py ++target-name ++hosts ++ports \
                    ++port-list-name +C +R +S
            ... start-alert-scan.gmp.py ++target-name ++hosts ++port-list-id \
                    +C ++recipient ++sender
            ... start-alert-scan.gmp.py ++target-id +C ++recipient ++sender
    """


def get_config(gmp, config, debug=False):
    # get all configs of the openvas instance
    # filter for all rows!
    res = gmp.get_configs(filter="rows=-1")

    if config < 0 or config > 4:
        raise ValueError("Wrong config identifier. Choose between [0,4].")
    # match the config abbreviation to accepted config names
    config_list = [
        'Full and fast',
        'Full and fast ultimate',
        'Full and very deep',
        'Full and very deep ultimate',
        'System Discovery',
    ]
    template_abbreviation_mapper = {
        0: config_list[0],
        1: config_list[1],
        2: config_list[2],
        3: config_list[3],
        4: config_list[4],
    }

    for conf in res.xpath('config'):
        cid = conf.xpath('@id')[0]
        name = conf.xpath('name/text()')[0]

        # get the config id of the desired template
        if template_abbreviation_mapper.get(config) == name:
            config_id = cid
            if debug:
                print(name + ": " + config_id)
            break

    return config_id


def get_target(
    gmp,
    target_name: str = None,
    hosts: List[str] = None,
    ports: str = None,
    port_list_name: str = None,
    port_list_id: str = None,
    debug: bool = True,
):
    if target_name is None:
        target_name = "target"
    targets = gmp.get_targets(filter=target_name)
    existing_targets = [""]
    for target in targets.findall("target"):
        existing_targets.append(str(target.find('name').text))
    counter = 0
    # iterate over existing targets and find a vacant targetName
    if target_name in existing_targets:
        while True:
            tmp_name = "{} ({})".format(target_name, str(counter))
            if tmp_name in existing_targets:
                counter += 1
            else:
                target_name = tmp_name
                break

    if debug:
        print("target name: {}".format(target_name))

    if not port_list_id:
        existing_port_lists = [""]
        port_lists_tree = gmp.get_port_lists()
        for plist in port_lists_tree.findall("port_list"):
            existing_port_lists.append(str(plist.find('name').text))

        print(existing_port_lists)

        if port_list_name is None:
            port_list_name = "portlist"

        if port_list_name in existing_port_lists:
            counter = 0
            while True:
                tmp_name = "{} ({})".format(port_list_name, str(counter))
                if tmp_name in existing_port_lists:
                    counter += 1
                else:
                    port_list_name = tmp_name
                    break

        port_list = gmp.create_port_list(port_list_name, ports)
        # create port list
        port_list_id = port_list.xpath('@id')[0]
        if debug:
            print("New Portlist-name:\t{}".format(str(port_list_name)))
            print("New Portlist-id:\t{}".format(str(port_list_id)))

    # integrate port list id into create_target
    res = gmp.create_target(target_name, hosts=hosts, port_list_id=port_list_id)
    print("New target '{}' created.".format(target_name))
    return res.xpath('@id')[0]


def get_alert(
    gmp,
    sender_email: str,
    recipient_email: str,
    alert_name: str = None,
    debug=False,
):

    # create alert if necessary
    alert_object = gmp.get_alerts(filter='name={}'.format(alert_name))
    alert = alert_object.xpath('alert')

    if len(alert) == 0:
        print("creating new alert {}".format(alert_name))
        gmp.create_alert(
            alert_name,
            event=gmp.types.AlertEvent.TASK_RUN_STATUS_CHANGED,
            event_data={"status": "Done"},
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

        alert_object = gmp.get_alerts(filter='name={}'.format(recipient_email))
        alert = alert_object.xpath('alert')

    alert_id = alert[0].get('id', 'no id found')
    if debug:
        print("alert_id: {}".format(str(alert_id)))

    return alert_id


def get_scanner(gmp):
    res = gmp.get_scanners()
    scanner_ids = res.xpath('scanner/@id')
    return scanner_ids[1]  # "default scanner"


def create_and_start_task(
    gmp,
    config_id: str,
    target_id: str,
    scanner_id: str,
    alert_id: str,
    alert_name: str,
    debug: bool = False,
):
    # Create the task
    task_name = "Alert Scan for Alert {}".format(alert_name)
    tasks = gmp.get_tasks(filter="name~{}".format(task_name))
    if tasks is not None:
        task_name = "Alert Scan for Alert {} ({})".format(
            alert_name, len(tasks.xpath('tasks/@id'))
        )
    task_comment = "Alert Scan"
    res = gmp.create_task(
        task_name,
        config_id,
        target_id,
        scanner_id,
        alert_ids=[alert_id],
        comment=task_comment,
    )

    # Start the task
    task_id = res.xpath('@id')[0]
    gmp.start_task(task_id)

    print('Task started: ' + task_name)

    if debug:
        # Stop the task (for performance reasons)
        gmp.stop_task(task_id)
        print('Task stopped')


def parse_args(args):
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description=HELP_TEXT,
    )

    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )

    target = parser.add_mutually_exclusive_group(required=True)

    target.add_argument(
        "++target-id",
        type=str,
        dest="target_id",
        help="Use an existing target by target id",
    )

    target.add_argument(
        "++target-name",
        type=str,
        dest="target_name",
        help="Create a target by name",
    )

    parser.add_argument(
        "++hosts",
        nargs='+',
        dest='hosts',
        help="Host(s) for the new target",
    )

    ports = parser.add_mutually_exclusive_group()

    ports.add_argument(
        "++port-list-id",
        type=str,
        dest="port_list_id",
        help="An existing portlist id for the new target",
    )
    ports.add_argument(
        "++ports",
        type=str,
        dest='ports',
        help="Ports in the new target: e.g. T:80-80,8080",
    )

    parser.add_argument(
        "++port-list-name",
        type=str,
        dest="port_list_name",
        help="Name for the new portlist in the new target",
    )

    config = parser.add_mutually_exclusive_group()

    config.add_argument(
        "+C",
        "++scan-config",
        default=0,
        type=int,
        dest='config',
        help="Choose from existing scan config:"
        "\n  0: Full and fast"
        "\n  1: Full and fast ultimate"
        "\n  2: Full and very deep"
        "\n  3: Full and very deep ultimate"
        "\n  4: System Discovery",
    )

    config.add_argument(
        "++scan-config-id",
        type=str,
        dest='scan_config_id',
        help="Use existing scan config by id",
    )

    parser.add_argument(
        "++scanner-id",
        type=str,
        dest='scanner_id',
        help="Use existing scanner by id",
    )

    parser.add_argument(
        "+R",
        "++recipient",
        required=True,
        dest='recipient_email',
        type=str,
        help="Alert recipient E-Mail address",
    )

    parser.add_argument(
        "+S",
        "++sender",
        required=True,
        dest='sender_email',
        type=str,
        help="Alert senders E-Mail address",
    )

    parser.add_argument(
        "++alert-name",
        dest='alert_name',
        type=str,
        help="Optional Alert name",
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def main(gmp, args):
    # pylint: disable=undefined-variable, unused-argument

    script_args = parse_args(args)

    # set alert_name to recipient email if no other name
    # is given
    if script_args.alert_name is None:
        script_args.alert_name = script_args.recipient_email

    # use existing config from argument
    if not script_args.scan_config_id:
        config_id = get_config(gmp, script_args.config)
    else:
        config_id = script_args.scan_config_id

    # create new target or use existing one from id
    if not script_args.target_id:
        target_id = get_target(
            gmp,
            target_name=script_args.target_name,
            hosts=script_args.hosts,
            ports=script_args.ports,
            port_list_name=script_args.port_list_name,
            port_list_id=script_args.port_list_id,
        )
    else:
        target_id = script_args.target_id
    alert_id = get_alert(
        gmp,
        script_args.sender_email,
        script_args.recipient_email,
        script_args.alert_name,
    )
    if not script_args.scanner_id:
        scanner_id = get_scanner(gmp)
    else:
        scanner_id = script_args.scanner_id

    create_and_start_task(
        gmp, config_id, target_id, scanner_id, alert_id, script_args.alert_name
    )

    print("\nScript finished\n")


if __name__ == '__gmp__':
    main(gmp, args)
