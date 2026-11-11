# SPDX-FileCopyrightText: 2026 Rylen Anil
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

from lxml import etree

from . import load_script


class CheckGmpTestCase(unittest.TestCase):
    def setUp(self):
        self.check_gmp = load_script(
            Path(__file__).absolute().parents[2] / "scripts",
            "check-gmp-gos24.10",
        )

    def check_report(self, threats, arguments=(), hostaddress=""):
        report = etree.Element("report")
        results = etree.SubElement(report, "results")
        for threat in threats:
            result = etree.SubElement(results, "result")
            etree.SubElement(result, "host").text = "192.0.2.1"
            etree.SubElement(result, "threat").text = threat

        gmp = MagicMock()
        with (
            patch.object(self.check_gmp, "InstanceManager") as manager,
            patch.object(self.check_gmp, "status") as status,
            patch.object(self.check_gmp.sys, "argv", ["gvm-script"]),
            patch("builtins.print") as output,
        ):
            status.side_effect = lambda _gmp, im, args: (
                self.check_gmp.filter_report(im, report, args)
            )
            script_args = [*arguments]
            if hostaddress:
                script_args.extend(["--hostaddress", hostaddress])
            with self.assertRaises(SystemExit) as raised:
                self.check_gmp.main(gmp, Namespace(script_args=script_args))
            manager.return_value.close_db.assert_called_once_with()
        return raised.exception.code, [
            call.args[0] for call in output.call_args_list
        ]

    def test_default_statuses(self):
        cases = [
            ([], 0),
            (["Low"], 0),
            (["Log"], 0),
            (["Medium"], 1),
            (["Medium"] * 20, 1),
            (["High"], 2),
            (["Critical"], 2),
        ]
        for threats, expected in cases:
            with self.subTest(threats=threats):
                code, _ = self.check_report(threats)
                self.assertEqual(code, expected)

    def test_warning_threshold_boundary(self):
        for count, expected in [(9, 0), (10, 0), (11, 1)]:
            with self.subTest(count=count):
                code, output = self.check_report(
                    ["Medium"] * count, ["--medium-warn", "10"]
                )
                self.assertEqual(code, expected)
                self.assertIn(f"Medium: {count}", output[0])
                self.assertIn(f"Medium={count}", output[-1])

    def test_critical_threshold_boundary(self):
        for count, expected in [(19, 1), (20, 1), (21, 2)]:
            with self.subTest(count=count):
                code, _ = self.check_report(
                    ["Medium"] * count,
                    ["--medium-warn", "10", "--medium-crit", "20"],
                )
                self.assertEqual(code, expected)

    def test_zero_disables_medium_critical_threshold(self):
        code, _ = self.check_report(["Medium"] * 21, ["--medium-crit", "0"])
        self.assertEqual(code, 1)

    def test_medium_critical_takes_precedence_over_warning(self):
        code, _ = self.check_report(
            ["Medium"] * 2,
            ["--medium-warn", "10", "--medium-crit", "1"],
        )
        self.assertEqual(code, 2)

    def test_high_and_critical_always_critical(self):
        for threat in ["High", "Critical"]:
            with self.subTest(threat=threat):
                code, _ = self.check_report(
                    [threat, "Medium"],
                    ["--medium-warn", "100", "--medium-crit", "200"],
                )
                self.assertEqual(code, 2)

    def test_thresholds_only_count_selected_host(self):
        code, _ = self.check_report(
            ["Medium"] * 21,
            ["--medium-warn", "10", "--medium-crit", "20"],
            hostaddress="192.0.2.2",
        )
        self.assertEqual(code, 0)

    def test_empty_as_unknown_is_preserved(self):
        code, _ = self.check_report([], ["--medium-warn", "10", "-e"])
        self.assertEqual(code, 3)

    def test_invalid_thresholds_fail_before_creating_session(self):
        for flag in ["--medium-warn", "--medium-crit"]:
            for value in ["-1", "1.5", "invalid"]:
                with (
                    self.subTest(flag=flag, value=value),
                    patch.object(self.check_gmp, "InstanceManager") as manager,
                    patch.object(self.check_gmp.sys, "stderr"),
                ):
                    gmp = MagicMock()
                    with self.assertRaises(SystemExit) as raised:
                        self.check_gmp.main(
                            gmp, Namespace(script_args=[flag, value])
                        )
                    self.assertEqual(raised.exception.code, 2)
                    manager.assert_not_called()
                    gmp.get_version.assert_not_called()
