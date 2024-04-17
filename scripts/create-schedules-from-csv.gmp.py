# -*- coding: utf-8 -*-
#
# Loosely based on the create-targets-from-host-list.gmp.py
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
# Run with gvm-script --gmp-username admin-user --gmp-password password socket create-schedules-from-csv.gmp.py schedules.csv
#
#

import sys
import time
import csv

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path
from typing import List
from gvm.errors import GvmResponseError

from gvm.protocols.gmp import Gmp

from gvmtools.helper import error_and_exit

HELP_TEXT = (
    "This script pulls schedule information "
    "from a csv file and creates a schedule for each row. \n"
    "use the same schedule names when creating tasks! \n\n"
    "csv file may contain Name of schedule, Timezone, Icalendar entry \n"
    "Use example schedules.csv as a template \n\n"
    "It should be rather self explanatory."
)


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 2:
        message = """
        This script pulls schedules from a csv file and creates a \
schedule for each row in the csv file.
        One parameter after the script name is required.

        1. <schedules_csvfile>  -- csv file containing names and secrets required for scan schedules

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/create_schedules_from_csv.gmp.py \
<schedules-csvfile>
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
        "sched_file",
        type=str,
        help=("CSV File containing schedules"),
    )
    script_args, _ = parser.parse_known_args(args)
    return script_args

def schedule_id(
    gmp: Gmp,
    schedule_name: str,
):
    response_xml = gmp.get_schedules(filter_string="rows=-1, name=" + schedule_name)
    schedules_xml = response_xml.xpath("schedule")
    schedule_id = ""

    for schedule in schedules_xml:
        name = "".join(schedule.xpath("name/text()"))
        schedule_id = schedule.get("id")
    return schedule_id


def create_schedules(   
    gmp: Gmp,
    sched_file: Path,
):
    try:
        numberschedules = 0
        with open(sched_file, encoding="utf-8") as csvFile:
            content = csv.reader(csvFile, delimiter=',')  #read the data
            for row in content:   #loop through each row
                if len(row) == 0:
                    continue
                sched_name = row[0]
                sched_tz = row[1]
                sched_ical = row[2]
                comment = f"Created: {time.strftime('%Y/%m/%d-%H:%M:%S')}"
                try:
                    if schedule_id(gmp, sched_name):
                        print(f"Schedule: {sched_name} exist, not creating...")
                        continue
                    print("Creating schedule: " + sched_name)
                    gmp.create_schedule(
                            name=sched_name,
                            timezone=sched_tz,
                            icalendar=sched_ical,
                            comment=comment
                    )
                    numberschedules = numberschedules + 1
                except GvmResponseError as gvmerr:
                    print(f"{gvmerr=}, name: {sched_name}")
                    pass
        csvFile.close()   #close the csv file

    except IOError as e:
        error_and_exit(f"Failed to read sched_file: {str(e)} (exit)")

    if len(row) == 0:
        error_and_exit("schedules file is empty (exit)")
    
    return numberschedules
    
def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    if args.script:
        args = args.script[1:]

    parsed_args = parse_args(args=args)

    print(
        "Creating schedules.\n"
    )

    numberschedules = create_schedules(
        gmp,
        parsed_args.sched_file,
    )

    numberschedules = str(numberschedules)
    print("    [" + numberschedules + "] schedule(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)
