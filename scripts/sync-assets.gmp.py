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

import csv
import sys


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script reads asset data from a csv file and sync it with the gsm.
        It needs one parameters after the script name.

        1. <csv_file> - should contain a table of IP-addresses with an optional a comment

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/sync-assets.gmp.py <csv_file>
        """
        print(message)
        sys.exit()


def sync_assets(gmp, filename):
    with open(filename, newline='') as f:
        reader = csv.reader(f, delimiter=',', quotechar='|')
        for row in reader:
            if len(row) == 2:
                ip = row[0]
                comment = row[1]
                # print('%s %s %s %s' % (host, ip, contact, location))

                # check if asset is already there
                ret = gmp.get_assets(
                    asset_type=gmp.types.AssetType.HOST, filter='ip=%s' % ip
                )
                if ret.xpath('asset'):
                    print('\nAsset with IP %s exist' % ip)
                    asset_id = ret.xpath('asset/@id')[0]
                    gmp.delete_asset(asset_id=asset_id)
                else:
                    print('Asset with ip %s does not exist. Sync...' % ip)
                    ret = gmp.create_host(name=ip, comment=comment)

                    if 'OK' in ret.xpath('@status_text')[0]:
                        print('Asset synced')


def main(gmp, args):
    # pylint: disable=undefined-variable

    check_args(args)

    file = args.script[1]

    sync_assets(gmp, file)


if __name__ == '__gmp__':
    main(gmp, args)
