# SPDX-FileCopyrightText: 2014 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp


def main(gmp: Gmp, args: Namespace) -> None:

    print("Emptying Trash...\n")

    try:
        status_text = gmp.empty_trashcan().xpath("@status_text")[0]
        print(status_text)
    except Exception as e:
        print(f"{e=}")


if __name__ == "__gmp__":
    main(gmp, args)
