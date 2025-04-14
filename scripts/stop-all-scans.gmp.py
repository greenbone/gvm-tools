# SPDX-FileCopyrightText: 2024 Martin Boller
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp


def stop_tasks(gmp: Gmp) -> None:
    tasks = gmp.get_tasks(
        filter_string="rows=-1 status=Running or status=Requested or status=Queued"
    )
    try:
        for task_id in tasks.xpath("task/@id"):
            print(f"Stopping task {task_id} ... ")
            status_text = gmp.stop_task(task_id).xpath("@status_text")[0]
            print(status_text)
    except Exception as e:
        print(f"{e=}")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable
    print("This script stops all tasks on the system.\n")

    stop_tasks(gmp)


if __name__ == "__gmp__":
    main(gmp, args)
