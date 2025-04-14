# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_schedules(filter_string="rows=-1")
    schedules_xml = response_xml.xpath("schedule")

    heading = ["#", "Name", "Id", "TZ", "iCalendar"]

    rows = []
    numberRows = 0

    print("Listing schedules.\n")

    for schedule in schedules_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(schedule.xpath("name/text()"))
        schedule_id = schedule.get("id")
        icalendar = "".join(schedule.xpath("icalendar/text()"))
        timezone = "".join(schedule.xpath("timezone/text()"))
        rows.append([rowNumber, name, schedule_id, timezone, icalendar])
        # print(icalendar)

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
