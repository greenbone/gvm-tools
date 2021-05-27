# -*- coding: utf-8 -*-
# Copyright (C) 2017-2021 Greenbone Networks GmbH
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
    if len_args != 1:
        message = """
        This script will display all hosts with the searched applications!

        1. <application>  -- Name of the application

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/application-detection.gmp.py <application>
        """
        print(message)
        sys.exit()


def print_assets(gmp, appname):
    res = gmp.get_reports()

    hosts = res.xpath('//host')

    for host in hosts:
        ip = host.xpath('ip/text()')
        hostname = host.xpath('detail/name[text()="hostname"]/../value/text()')
        if len(hostname) == 0:
            hostname = ""
        else:
            hostname = hostname[0]

        print('{ip} ({hostname})'.format(ip=ip, hostname=hostname))
        apps = host.xpath(
            'detail/name[text() = "App"]/../value['
            'contains(text(), "{0}")]/text()'.format(appname)
        )
        for app in apps:
            print('\t' + app)
        print('\n')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    print_assets(gmp, args.script[1])


if __name__ == '__gmp__':
    main(gmp, args)
