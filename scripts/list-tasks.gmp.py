# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table
from datetime import datetime


def list_tasks(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_tasks(details=True, filter_string="rows=-1")
    tasks_xml = response_xml.xpath("task")

    heading = [
        "#",
        "Name",
        "Id",
        "Target",
        "Scanner",
        "Scan Order",
        "Severity",
        "Average Duration",
        "Last Scan Duration (hours)",
    ]

    rows = []
    numberRows = 0

    for task in tasks_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(task.xpath("name/text()"))
        task_id = task.get("id")
        targetname = "".join(task.xpath("target/name/text()"))
        scanner = "".join(task.xpath("scanner/name/text()"))
        severity = "".join(task.xpath("last_report/report/severity/text()"))
        order = "".join(task.xpath("hosts_ordering/text()"))
        average_duration = "".join(task.xpath("average_duration/text()"))
        average_duration_int = (
            0 if not average_duration else int(average_duration)
        )
        average_duration_hours = f"{average_duration_int / 3600:.2f}"
        scan_start_iso = "".join(
            task.xpath("last_report/report/scan_start/text()")
        )
        scan_end_iso = "".join(task.xpath("last_report/report/scan_end/text()"))
        if not scan_start_iso or not scan_end_iso:
            duration_hours = ""
        else:
            scan_start_time = datetime.fromisoformat(
                scan_start_iso.replace("Z", "+00:00")
            )
            scan_end_time = datetime.fromisoformat(
                scan_end_iso.replace("Z", "+00:00")
            )
            duration = scan_end_time - scan_start_time
            duration_hours = f"{duration.total_seconds() / 3600:.2f}"
        rows.append(
            [
                rowNumber,
                name,
                task_id,
                targetname,
                scanner,
                order,
                severity,
                average_duration_hours,
                duration_hours,
            ]
        )

    print(Table(heading=heading, rows=rows))


def main(gmp: Gmp, args: Namespace) -> None:

    print("Listing tasks.\n")

    list_tasks(gmp, args)


if __name__ == "__gmp__":
    main(gmp, args)
