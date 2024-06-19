# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_tasks(details=True, filter_string="rows=-1")
    tasks_xml = response_xml.xpath("task")

    heading = ["#", "Name", "Id", "Target", "Scanner", "Scan Order", "Severity"]

    rows = []
    numberRows = 0

    print("Listing tasks.\n")

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
        rows.append(
            [rowNumber, name, task_id, targetname, scanner, order, severity]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
