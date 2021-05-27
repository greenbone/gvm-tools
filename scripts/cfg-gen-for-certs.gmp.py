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
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp


def check_args(args):
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script creates a new scan config with nvts from a given CERT-Bund!
        It needs one parameter after the script name.

        1. <cert>   -- Name or ID of the CERT-Bund

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/cfg-gen-for-certs.gmp.py CB-K16/0943
        """
        print(message)
        sys.exit()


def create_scan_config(gmp, cert_bund_name):
    cert_bund_details = gmp.get_info(
        info_id=cert_bund_name, info_type=gmp.types.InfoType.CERT_BUND_ADV
    )

    list_cves = cert_bund_details.xpath(
        'info/cert_bund_adv/raw_data/Advisory/CVEList/CVE/text()'
    )

    nvt_dict = dict()
    counter = 0

    for cve in list_cves:
        # Get all nvts of this cve
        cve_info = gmp.get_info(info_id=cve, info_type=gmp.types.InfoType.CVE)
        nvts = cve_info.xpath('info/cve/nvts/nvt')

        for nvt in nvts:
            counter += 1
            oid = nvt.xpath('@oid')[0]

            # We need the nvt family to modify scan config
            nvt_data = gmp.get_scan_config_nvt(oid)
            family = nvt_data.xpath('nvt/family/text()')[0]

            # Create key value map
            if family in nvt_dict and oid not in nvt_dict[family]:
                nvt_dict[family].append(oid)
            else:
                nvt_dict[family] = [oid]

    # Create new config
    copy_id = '085569ce-73ed-11df-83c3-002264764cea'
    config_name = 'scanconfig_for_%s' % cert_bund_name
    config_id = ''

    try:
        res = gmp.create_scan_config(copy_id, config_name)
        config_id = res.xpath('@id')[0]

        # Modify the config with the nvts oid
        for family, nvt_oid in nvt_dict.items():
            gmp.modify_scan_config(
                config_id=config_id, nvt_oids=nvt_oid, family=family
            )

        # This nvts must be present to work
        family = 'Port scanners'
        nvts = ['1.3.6.1.4.1.25623.1.0.14259', '1.3.6.1.4.1.25623.1.0.100315']
        gmp.modify_scan_config(
            config_id=config_id, nvt_oids=nvts, family=family
        )

    except GvmError:
        print('Config exist')


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    cert_bund_name = args.script[1]

    print('Creating scan config for {0}'.format(cert_bund_name))

    create_scan_config(gmp, cert_bund_name)


if __name__ == '__gmp__':
    main(gmp, args)
