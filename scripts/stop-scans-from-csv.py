# -*- coding: utf-8 -*-
#
# Loosely based on Greenbone sample scripts
# As provided by Greenbone in the gvm-tools repo
#
# Martin Boller
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
#
# Run with gvm-script --gmp-username admin-user --gmp-password password socket start-scans-from-csv.gmp.py startscans.csv
#

import sys
import time
import csv
import json

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List
from gvm.errors import GvmResponseError

from gvm.protocols.gmp import Gmp

from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls task names from a csv file and starts the tasks listed in every row. \n"
)

def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls tasks from a csv file and creates a \
task for each row in the csv file.
        One parameter after the script name is required.

        1. <tasks_csvfile>  -- csv file containing names and secrets required for scan tasks

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/stop_tasks_from_csv.gmp.py \
<tasks-csvfile>
        """
        print(message)
        sys.exit()


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
        "task_file",
        type=str,
        help=("CSV File containing tasks"),
    )
    script_args, _ = parser.parse_known_args(args)
    return script_args

def task_id(
    gmp: Gmp,
    task_name: str,
):
    response_xml = gmp.get_tasks(filter_string="rows=-1, status=Running "
        "or status=Requested "
        "or status=Queued "
        "and name=" + task_name)
    tasks_xml = response_xml.xpath("task")
    task_id = ""

    for task in tasks_xml:
        name = "".join(task.xpath("name/text()"))
        task_id = task.get("id")
        #print("Requesting stop of task: " + task_name + " Task UUID: " + task_id)
    return task_id

def stop_tasks(   
    gmp: Gmp,
    task_file: Path,
):
    try:
        numbertasks = 0
        with open(task_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=',')  #read the data
            try:
                for row in content:   #loop through each row
                    if len(row) == 0:
                        continue
                    task_stop = task_id(gmp, row[0])
                    if task_stop:
                        numbertasks = numbertasks + 1
                        print(f"Stopping task name: {row[0]} with uuid: {task_stop} ...")
                        status_text = gmp.stop_task(task_stop).xpath(
                        "@status_text"
                        )[0]
                        print(status_text)
                    else:
                        print("Task " + row[0] + " is either in status Stopped, Stop Requested, or does not exist on this system.\n")
            except GvmResponseError as gvmerr:
                print(f"{gvmerr=}, task: {task_stop}")
                pass
        csvFile.close()   #close the csv file

    except IOError as e:
        error_and_exit(f"Failed to read task_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("tasks file is empty (exit)")
    
    return numbertasks
    
def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    print(
        "Stopping tasks.\n"
    )

    numbertasks = stop_tasks(
        gmp,
        parsed_args.task_file,
    )

    numbertasks = str(numbertasks)
    print("   \n [" + numbertasks + "] task(s)/scan(s) stopped!\n")

if __name__ == "__gmp__":
    main(gmp, args)
