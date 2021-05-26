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

import time
import sys
from argparse import Namespace
from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1

    if len_args != 1:
        message = """
        This script deletes overrides with a specific filter value

        <filter>  -- the parameter for the filter.

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/delete-overrides-by-filter.gmp.py <filter>
        """
        print(message)
        sys.exit()


def delete_overrides(gmp, filter_value):
    filters = gmp.get_overrides(filter=filter_value)

    if not filters.xpath('override'):
        print('No overrides with filter: %s' % filter_value)

    for f_id in filters.xpath('override/@id'):
        print('Delete override: %s' % f_id, end='')
        res = gmp.delete_override(f_id)

        if 'OK' in res.xpath('@status_text')[0]:
            print(' OK')
        else:
            print(' ERROR')

        time.sleep(60)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    filter_value = args.script[1]

    delete_overrides(gmp, filter_value)


if __name__ == '__gmp__':
    main(gmp, args)
