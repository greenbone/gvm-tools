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
#
# Based on other Greenbone scripts 
#
# Martin Boller
#

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvmtools.helper import Table

#from gvm.xml import pretty_print

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_feeds()
    feeds_xml = response_xml.xpath("feed")
    heading = ["#", "Name", "Version", "Status"]
    rows = []
    numberRows = 0
#    pretty_print(feeds_xml)

    print(
        "Listing feeds and their status.\n"
    )

    for feed in feeds_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        name = "".join(feed.xpath("name/text()"))
        version = "".join(feed.xpath("version/text()"))
        type = "".join(feed.xpath("type/text()"))
        status = "".join(feed.xpath("currently_syncing/timestamp/text()"))
        if not status:
            status = "Up-to-date..."
        else:
            status = "Update in progress..."


        rows.append([rowNumber, name, version, status])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
