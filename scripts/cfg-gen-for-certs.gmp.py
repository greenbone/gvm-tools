# SPDX-FileCopyrightText: 2017-2021 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

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


WHOLE_ONLY_FAMILIES = [
    "AIX Local Security Checks",
    "AlmaLinux Local Security Checks",
    "Amazon Linux Local Security Checks",
    "Arch Linux Local Security Checks",
    "CentOS Local Security Checks",
    "Debian Local Security Checks",
    "Fedora Local Security Checks",
    "FreeBSD Local Security Checks",
    "Gentoo Local Security Checks",
    "HCE Local Security Checks",
    "HP-UX Local Security Checks",
    "Huawei EulerOS Local Security Checks",
    "Mageia Linux Local Security Checks",
    "Mandrake Local Security Checks",
    "openEuler Local Security Checks",
    "openSUSE Local Security Checks",
    "Oracle Linux Local Security Checks",
    "Red Hat Local Security Checks",
    "Rocky Linux Local Security Checks",
    "Slackware Local Security Checks",
    "Solaris Local Security Checks",
    "SuSE Local Security Checks",
    "Ubuntu Local Security Checks",
    "Windows Local Security Checks",
]


def create_scan_config(gmp, cert_bund_name):
    cert_bund_details = gmp.get_info(
        info_id=cert_bund_name, info_type=gmp.types.InfoType.CERT_BUND_ADV
    )

    list_cves = cert_bund_details.xpath(
        "info/cert_bund_adv/raw_data/Advisory/CVEList/CVE/text()"
    )

    nvt_dict = dict()
    whole_families = set()
    counter = 0

    for cve in list_cves:
        # Get all nvts of this cve
        cve_info = gmp.get_info(info_id=cve, info_type=gmp.types.InfoType.CVE)
        nvts = cve_info.xpath("info/cve/nvts/nvt")

        for nvt in nvts:
            counter += 1
            oid = nvt.xpath("@oid")[0]

            # We need the nvt family to modify scan config
            nvt_data = gmp.get_scan_config_nvt(oid)
            family = nvt_data.xpath("nvt/family/text()")[0]

            # Collect list of whole-only families
            if family in WHOLE_ONLY_FAMILIES:
                if family not in whole_families:
                    whole_families.add(family)
            # Create key value map
            elif family in nvt_dict and oid not in nvt_dict[family]:
                nvt_dict[family].append(oid)
            else:
                nvt_dict[family] = [oid]

    # Create new config
    copy_id = "085569ce-73ed-11df-83c3-002264764cea"
    config_name = f"scanconfig_for_{cert_bund_name}"
    config_id = ""

    try:
        res = gmp.create_scan_config(copy_id, config_name)
        config_id = res.xpath("@id")[0]

        # Modify the config with the nvts oid
        for family, nvt_oid in nvt_dict.items():
            try:
                gmp.modify_scan_config_set_nvt_selection(
                    config_id=config_id, nvt_oids=nvt_oid, family=family
                )
            except GvmError as gvmerr:
                if (
                    "Attempt to modify NVT in whole-only family"
                    in gvmerr.message
                ):
                    print(
                        f'WARNING: Adding whole family "{family}" to scan config"'
                        f"(Please add {family} to WHOLE_ONLY_FAMILIES array)"
                    )
                    whole_families.add(family)
                else:
                    print(f"Could not modify scan config, {gvmerr=}")

        if len(whole_families) > 0:
            print(f"Adding whole families: {whole_families}")

            gmp.modify_scan_config_set_family_selection(
                config_id=config_id,
                families=[(f, True, True) for f in whole_families],
            )

        # This nvts must be present to work
        family = "Port scanners"
        nvts = ["1.3.6.1.4.1.25623.1.0.14259", "1.3.6.1.4.1.25623.1.0.100315"]
        gmp.modify_scan_config_set_nvt_selection(
            config_id=config_id, nvt_oids=nvts, family=family
        )

        print("Finished")

    except GvmError as e:
        print("Config exist ", e)


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    cert_bund_name = args.script[1]

    print(f"Creating scan config for {cert_bund_name}")

    create_scan_config(gmp, cert_bund_name)


if __name__ == "__gmp__":
    main(gmp, args)
