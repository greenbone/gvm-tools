# -*- coding: utf-8 -*-
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
#
# Based on other Greenbone scripts 
#
# Martin Boller
#

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_alerts(filter_string="rows=-1")
    alerts_xml = response_xml.xpath("alert")

    heading = ["#", "Name", "Id", "Event", "Event type", "Method", "Condition", "In use"]

    rows = []
    numberRows = 0

    print(
        "Listing alerts.\n"
    )

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

        rows.append([rowNumber, name, alert_id, alert_event, alert_event_type, alert_method, alert_condition, alert_inuse])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
