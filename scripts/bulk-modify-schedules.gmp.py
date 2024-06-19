# SPDX-FileCopyrightText: 2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from argparse import Namespace

from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1

    if len_args != 3:
        message = """
        This script modifies the timezone and/or icalendar of all schedules
        in a filter selection.

        <filter>    -- the filter text used to filter the schedules.
        <timezone>  -- the new timezone to set or empty to keep existing one.
        <icalendar> -- the new icalendar to set or empty to keep existing one.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \\
                ssh --hostname <gsm> scripts/bulk-modify-schedules.gmp.py \\
                <filter> <timezone> <icalendar>
        """
        print(message)
        sys.exit()


def bulk_modify_schedules(gmp, filter_term, new_timezone, new_icalendar):
    get_response = gmp.get_schedules(filter=filter_term)
    schedules = get_response.findall("schedule")

    for schedule in schedules:
        uuid = schedule.attrib["id"]
        name = schedule.find("name").text
        comment = schedule.find("comment").text

        if new_timezone:
            timezone = new_timezone
        else:
            timezone = schedule.find("timezone").text

        if new_icalendar:
            icalendar = new_icalendar
        else:
            icalendar = schedule.find("icalendar").text

        print(f"- Modifying {name} ({uuid})")

        gmp.modify_schedule(
            uuid,
            name=name,
            comment=comment,
            timezone=timezone,
            icalendar=icalendar,
        )


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    check_args(args)

    filter_term = args.script[1]
    new_timezone = args.script[2]
    new_icalendar = args.script[3]

    bulk_modify_schedules(gmp, filter_term, new_timezone, new_icalendar)


if __name__ == "__gmp__":
    main(gmp, args)
