# -*- coding: utf-8 -*-
# Copyright (C) 2019-2021 Greenbone Networks GmbH
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
#
# Based on other Greenbone scripts 
#
# Martin Boller
#

from argparse import Namespace

from gvm.protocols.gmp import Gmp

from gvmtools.helper import Table

def stop_tasks(gmp: Gmp) -> None:
    tasks = gmp.get_tasks(
            filter_string="rows=-1 status=Running or status=Requested or status=Queued"
        )
    try:
        for task_id in tasks.xpath("task/@id"):
            print(f"Stopping task {task_id} ... ")
            gmp.stop_task(task_id).xpath(
                "@status_text"
            )[0]
            print(status_text)
    except:
        pass

def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    print(
        "This script stops all tasks on the system.\n"
    )

    stop_tasks(gmp)
    
if __name__ == "__gmp__":
    main(gmp, args)
