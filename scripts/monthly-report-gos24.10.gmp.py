# SPDX-FileCopyrightText: 2017-2024 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace, RawDescriptionHelpFormatter
from datetime import date, datetime, timedelta

from gvm.protocols.gmp import Gmp
from terminaltables import AsciiTable


def print_reports(
    gmp: Gmp, from_date: date, to_date: date, reports_choice: str
) -> None:
    host_filter = (
        f"rows=-1 and modified>{from_date.isoformat()} "
        f"and created<{to_date.isoformat()}"
    )

    hosts_xml = gmp.get_hosts(filter_string=host_filter)

    sum_critical = 0
    sum_high = 0
    sum_medium = 0
    sum_low = 0

    if reports_choice == "last":
        table_header = [
            "Hostname",
            "IP",
            "Report",
            "Critical",
            "High",
            "Medium",
            "Low",
        ]
    elif reports_choice == "list":
        table_header = [
            "Hostname",
            "IP",
            "Reports",
            "Critical",
            "High",
            "Medium",
            "Low",
        ]
    else:
        table_header = ["Hostname", "IP", "Critical", "High", "Medium", "Low"]

    table_data = [table_header]

    for host in hosts_xml.xpath("asset"):
        ip = host.xpath("name/text()")[0]

        hostnames = host.xpath(
            'identifiers/identifier/name[text()="hostname"]/../value/text()'
        )

        if len(hostnames) == 0:
            continue

        hostname = hostnames[0]

        results = gmp.get_results(
            details=False,
            filter_string=(
                f"rows=-1 host={ip} and severity>0.0"
                f" and modified>{from_date.isoformat()}"
                f" and modified<{to_date.isoformat()}"
            ),
        )

        unique_vt_results = results.xpath(
            "result["
            "  not (./nvt/@oid = preceding-sibling::result/nvt/@oid)"
            "]"
        )
        if len(unique_vt_results) == 0:
            continue

        low = medium = high = critical = 0
        for result in unique_vt_results:
            threat = result.findtext("threat")
            if threat == "Critical":
                critical += 1
            elif threat == "High":
                high += 1
            elif threat == "Medium":
                medium += 1
            elif threat == "Low":
                low += 1

        sum_low += low
        sum_medium += medium
        sum_high += high
        sum_critical += critical

        if reports_choice == "none":
            table_data.append([hostname, ip, critical, high, medium, low])
        else:
            report_host_identifiers = host.xpath(
                "identifiers/identifier[source/deleted = 0 and"
                '  (source/type = "Report Host"'
                '   or source/type = "Report Host Detail")]'
            )
            report_ids = []
            for identifier in report_host_identifiers:
                mod_date = datetime.fromisoformat(
                    identifier.findtext("modification_time")
                ).date()

                if mod_date >= to_date or mod_date < from_date:
                    continue

                report_ids.append(identifier.find("source").get("id"))
                if reports_choice == "last":
                    break

            if reports_choice == "last":
                table_data.append(
                    [hostname, ip, report_ids[0], critical, high, medium, low]
                )
            else:
                table_data.append(
                    [
                        hostname,
                        ip,
                        ",\n".join(report_ids) + "\n",
                        critical,
                        high,
                        medium,
                        low,
                    ]
                )

    table = AsciiTable(table_data)
    print(f"{table.table}\n")
    print(
        f"Summary of results from {from_date.isoformat()} "
        f"to {to_date.isoformat()}"
    )
    print(f"Critical: {int(sum_critical)}")
    print(f"High: {int(sum_high)}")
    print(f"Medium: {int(sum_medium)}")
    print(f"Low: {int(sum_low)}\n\n")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    description_message = """
This script will display all vulnerabilities from the hosts of the \
reports in a given month and year.
These must be given after the script name as plain numbers.

This version is explicitly made for GOS 24.10.

Example:
    $ gvm-script --gmp-username name --gmp-password pass \
ssh --hostname <gsm> scripts/monthly-report2.gmp.py 05 2019
    """

    parser = ArgumentParser(
        prog=("gvm-script [...] " + args.script[0]),
        formatter_class=RawDescriptionHelpFormatter,
        prefix_chars="+",
        description=description_message,
    )
    parser.add_argument("month", type=int, help="month of the monthly report")
    parser.add_argument("year", type=int, help="year of the monthly report")
    parser.add_argument(
        "++reports",
        choices=["none", "last", "list"],
        default="last",
        help=(
            "what to show in the reports column:"
            ' "none": do not show a reports column;'
            ' "last": show the last report in the selected month;'
            ' "list": show a list of reports in the selected month.'
        ),
    )
    script_args, _ = parser.parse_known_args(args.script[1:])

    from_date = date(script_args.year, script_args.month, 1)
    to_date = from_date + timedelta(days=31)
    # To have the first day in month
    to_date = to_date.replace(day=1)

    print_reports(gmp, from_date, to_date, script_args.reports)


if __name__ == "__gmp__":
    main(gmp, args)
