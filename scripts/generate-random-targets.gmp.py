# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from argparse import Namespace
from random import choice, gauss

from gvm.protocols.gmp import Gmp
from gvmtools.helper import generate_random_ips


def check_args(args):
    len_args = len(args.script) - 1
    if len_args < 2:
        message = """
        This script generates random task data and feeds it to\
    a desired GSM
        It needs two parameters after the script name.

        1. <host_number> -- number of dummy hosts to select from
        2. <number>      -- number of targets to be generated

        In addition, if you would like for the number of targets generated
    to be randomized on a Gaussian distribution, add 'with-gauss'

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/gen-random-targets.gmp.py 3 40 with-gauss
        """
        print(message)
        sys.exit()


def generate(gmp, args, n_targets, n_ips):
    ips = generate_random_ips(n_ips)

    if "with-gauss" in args.script:
        n_targets = int(gauss(n_targets, 2))

    for i in range(n_targets):
        host_ip = choice(ips)
        index = f"{{0:0>{len(str(n_targets))}}}"
        name = f"Target_{index.format(i + 1)}"

        gmp.create_target(name=name, make_unique=True, hosts=[host_ip])


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    host_number = int(args.script[1])
    number_targets = int(args.script[2])

    print("Generating random targets...")

    generate(gmp, args, number_targets, host_number)


if __name__ == "__gmp__":
    main(gmp, args)
