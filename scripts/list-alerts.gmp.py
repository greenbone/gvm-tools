# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_alerts(filter_string="rows=-1")
    alerts_xml = response_xml.xpath("alert")

    heading = [
        "#",
        "Name",
        "Id",
        "Event",
        "Event type",
        "Method",
        "Condition",
        "In use",
    ]

    rows = []
    numberRows = 0

    print("Listing alerts.\n")

    for alert in alerts_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(alert.xpath("name/text()"))
        alert_id = alert.get("id")
        alert_condition = "".join(alert.xpath("condition/text()"))
        alert_method = "".join(alert.xpath("method/text()"))
        alert_event_type = "".join(alert.xpath("event/data/text()"))
        alert_event = "".join(alert.xpath("event/text()"))
        alert_inuse = "".join(alert.xpath("in_use/text()"))
        if alert_inuse == "1":
            alert_inuse = "Yes"
        else:
            alert_inuse = "No"

        rows.append(
            [
                rowNumber,
                name,
                alert_id,
                alert_event,
                alert_event_type,
                alert_method,
                alert_condition,
                alert_inuse,
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
