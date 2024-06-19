# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from argparse import ArgumentParser, FileType, Namespace, RawTextHelpFormatter
from typing import List

from gvm.protocols.gmp import Gmp
from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script will update target hosts information for a desired task.\n"
    'The given task needs to have the status "new".\n\n'
    "Example for starting up the routine:\n"
    "    $ gvm-script --gmp-username name --gmp-password pass "
    "ssh --hostname <gsm> scripts/update-task-target.gmp.py +hf hosts_file.csv "
    "+t 303fa0a6-aa9b-43c4-bac0-66ae0b2d1698"
)


def parse_args(args: Namespace) -> Namespace:  # pylint: disable=unused-argument
    """Parsing args ..."""

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

    parser.add_argument(
        "+t",
        "++task-id",
        type=str,
        required=True,
        dest="task_id",
        help="UUID of task to be modified",
    )

    hosts_args = parser.add_mutually_exclusive_group()

    hosts_args.add_argument(
        "+hl",
        "++host-list",
        nargs="+",
        type=str,
        dest="host_list",
        help="Use the given hosts (IPs) for the new target.",
    )

    hosts_args.add_argument(
        "+hf",
        "++host-file",
        type=FileType("r"),
        dest="host_file",
        help=".csv file containing desired target hosts separated by ','",
    )

    script_args, _ = parser.parse_known_args()
    return script_args


def load_host_file(filename) -> List[str]:
    host_list = list()

    try:
        for line in filename.readlines():
            host = line.split(",")[0]
            host = host.strip()
            if len(host) == 0:
                continue
            host_list.append(host)

    except IOError as e:
        error_and_exit(f"Failed to read host_file: {str(e)} (exit)")

    if len(host_list) == 0:
        error_and_exit("Host file is empty (exit)")

    return host_list


def copy_send_target(gmp, host_list, old_target_id):
    keywords = {"hosts": host_list}

    keywords["comment"] = (
        "This target was automatically "
        f'modified: {time.strftime("%Y/%m/%d-%H:%M:%S")}'
    )

    old_target = gmp.get_target(target_id=old_target_id)[0]

    objects = ("reverse_lookup_only", "reverse_lookup_unify", "name")
    for obj in objects:
        var = old_target.xpath(f"{obj}/text()")[0]
        if var == "0":
            var = ""
        keywords[f"{obj}"] = var

    port_list = {}
    port_list = old_target.xpath("port_list/@id")[0]
    keywords["port_list_id"] = port_list

    keywords["name"] += "_copy"  # the name must differ from existing names

    new_target_id = gmp.create_target(**keywords).xpath("@id")[0]

    print("\n  New target created!\n")
    print(f"Target_id:   {new_target_id}")
    print(f'Target_name: {keywords["name"]}\n')

    return new_target_id


def create_target_hosts(gmp: Gmp, host_file, task_id, old_target_id):
    new_target_id = copy_send_target(gmp, host_file, old_target_id)

    gmp.modify_task(task_id=task_id, target_id=new_target_id)

    print("  Task successfully modified!\n")


def check_to_delete(gmp: Gmp, target_id: str) -> None:
    target = gmp.get_target(target_id=target_id)[0]
    if "0" in target.xpath("in_use/text()"):
        gmp.delete_target(target_id=target_id)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    parsed_args = parse_args(args=args)

    host_list = parsed_args.host_list
    if parsed_args.host_file:
        host_list = load_host_file(filename=parsed_args.host_file)
    task_id = parsed_args.task_id

    task = gmp.get_task(task_id=task_id)[1]
    old_target_id = task.xpath("target/@id")[0]

    if old_target_id:
        create_target_hosts(gmp, host_list, task_id, old_target_id)
        check_to_delete(gmp, old_target_id)
    else:
        error_and_exit("The given task doesn't have an existing target.")


if __name__ == "__gmp__":
    main(gmp, args)
