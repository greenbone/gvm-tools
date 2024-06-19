# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_tickets(filter_string="rows=-1")
    tickets_xml = response_xml.xpath("ticket")

    heading = ["#", "ID", "Name", "Host", "Task", "Status", "Note"]

    rows = []
    numberRows = 0

    print("Listing tickets.\n")

    for ticket in tickets_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(ticket.xpath("name/text()"))
        ticket_id = ticket.get("id")
        ticket_status = "".join(ticket.xpath("status/text()"))
        ticket_task = "".join(ticket.xpath("task/name/text()"))
        ticket_host = "".join(ticket.xpath("host/text()"))
        if ticket_status.upper() == "OPEN":
            ticket_note = "".join(ticket.xpath("open_note/text()"))
        elif ticket_status.upper() == "FIXED":
            ticket_note = "".join(ticket.xpath("fixed_note/text()"))
        elif ticket_status.upper() == "CLOSED":
            ticket_note = "".join(ticket.xpath("closed_note/text()"))

        rows.append(
            [
                rowNumber,
                ticket_id,
                name,
                ticket_host,
                ticket_task,
                ticket_status,
                ticket_note,
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
