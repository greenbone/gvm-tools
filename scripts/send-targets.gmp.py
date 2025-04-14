# SPDX-FileCopyrightText: 2018-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import create_xml_tree, yes_or_no
from lxml.etree import Element


def check_args(args: Namespace) -> None:
    len_args = len(args.script) - 1
    if len_args != 1:
        message = """
        This script pulls target data from an xml document and feeds it to \
    a desired GSM
        One parameter after the script name is required.

        1. <xml_doc>  -- .xml file containing targets

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/send-targets.gmp.py example_file.xml
        """
        print(message)
        sys.exit()


def parse_send_xml_tree(gmp: Gmp, xml_tree: Element) -> None:
    credential_options = [
        "ssh_credential",
        "smb_credential",
        "esxi_credential",
        "snmp_credential",
    ]
    counter = 1

    for target in xml_tree.xpath("target"):
        keywords = {}  # {'make_unique': True}

        keywords["name"] = target.find("name").text

        keywords["hosts"] = target.find("hosts").text.split(",")

        exclude_hosts = target.find("exclude_hosts").text
        if exclude_hosts is not None:
            keywords["exclude_hosts"] = exclude_hosts.split(",")

        comment = target.find("comment").text
        if comment is not None:
            keywords["comment"] = comment

        credentials = gmp.get_credentials()[0].xpath("//credential/@id")

        for credential in credential_options:
            cred_id = target.find(credential).xpath("@id")[0]
            if cred_id == "":
                continue
            if cred_id not in credentials:
                response = yes_or_no(
                    f"\nThe credential '{credential}' for 'target {counter}' "
                    "could not be located...\nWould you like to continue?"
                )

                if response is False:
                    print("Terminating...\n")
                    sys.exit()
                else:
                    continue

            key = f"{credential}_id"
            keywords[key] = cred_id
            elem_path = target.find(credential)
            port = elem_path.find("port")
            if port is not None and port.text is not None:
                port_key = f"{credential}_port"
                keywords[port_key] = elem_path.find("port").text

        alive_test = gmp.types.AliveTest.from_string(
            target.find("alive_tests").text
        )

        if alive_test is not None:
            keywords["alive_test"] = alive_test

        reverse_lookup_only = target.find("reverse_lookup_only").text
        if reverse_lookup_only == "1":
            keywords["reverse_lookup_only"] = 1

        reverse_lookup_unify = target.find("reverse_lookup_unify").text
        if reverse_lookup_unify == "1":
            keywords["reverse_lookup_unify"] = 1

        port_range = target.find("port_range")
        if port_range is not None:
            keywords["port_range"] = port_range.text

        if target.xpath("port_list/@id") is not None:
            port_list = {}
            port_list = target.xpath("port_list/@id")[0]
            keywords["port_list_id"] = port_list

        print(keywords)

        gmp.create_target(**keywords)

        counter += 1


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    xml_doc = args.script[1]

    print("\nSending targets...")

    xml_tree = create_xml_tree(xml_doc)
    parse_send_xml_tree(gmp, xml_tree)

    print("\n  Target(s) created!\n")


if __name__ == "__gmp__":
    main(gmp, args)  # pylint: disable=undefined-variable
