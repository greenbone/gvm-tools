# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import time
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

    if not filters.xpath("override"):
        print(f"No overrides with filter: {filter_value}")

    for f_id in filters.xpath("override/@id"):
        print(f"Delete override: {f_id}", end="")
        res = gmp.delete_override(f_id)

        if "OK" in res.xpath("@status_text")[0]:
            print(" OK")
        else:
            print(" ERROR")

        time.sleep(60)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    filter_value = args.script[1]

    delete_overrides(gmp, filter_value)


if __name__ == "__gmp__":
    main(gmp, args)
