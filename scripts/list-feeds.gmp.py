# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table

# from gvm.xml import pretty_print


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_feeds()
    feeds_xml = response_xml.xpath("feed")
    heading = ["#", "Name", "Version", "Type", "Status"]
    rows = []
    numberRows = 0
    #    pretty_print(feeds_xml)

    print("Listing feeds and their status.\n")

    for feed in feeds_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)
        name = "".join(feed.xpath("name/text()"))
        version = "".join(feed.xpath("version/text()"))
        feed_type = "".join(feed.xpath("type/text()"))
        status = "".join(feed.xpath("currently_syncing/timestamp/text()"))
        if not status:
            status = "Up-to-date..."
        else:
            status = "Update in progress..."

        rows.append([rowNumber, name, version, feed_type, status])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
