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
from random import choice, gauss
from argparse import Namespace
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

    if 'with-gauss' in args.script:
        n_targets = int(gauss(n_targets, 2))

    for i in range(n_targets):
        host_ip = choice(ips)
        index = '{{0:0>{}}}'.format(len(str(n_targets)))
        name = 'Target_{}'.format(index.format(i + 1))

        gmp.create_target(name=name, make_unique=True, hosts=[host_ip])


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    host_number = int(args.script[1])
    number_targets = int(args.script[2])

    print('Generating random targets...')

    generate(gmp, args, number_targets, host_number)


if __name__ == '__gmp__':
    main(gmp, args)
