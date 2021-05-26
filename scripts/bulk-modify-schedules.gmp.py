# -*- coding: utf-8 -*-
# Copyright (C) 2021 Greenbone Networks GmbH
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

        print("- Modifying %s (%s)" % (name, uuid))

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
