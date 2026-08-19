# SPDX-FileCopyrightText: 2018-2024 Greenbone AG
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

import io
import logging
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from gvmtools.secrets import (
    REDACTED,
    clear_secrets,
    install_log_redaction,
    read_password_file,
    redact,
    redact_argument_tokens,
    redacted_arguments,
    register_secret,
    resolve_password,
)

SECRET = "Sup3rG3h3im!2026"


class RedactTestCase(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_registered_secret_is_replaced(self):
        register_secret(SECRET)

        self.assertEqual(
            redact(f"login with {SECRET}"), f"login with {REDACTED}"
        )

    def test_unregistered_text_is_untouched(self):
        register_secret(SECRET)

        self.assertEqual(redact("nothing to hide"), "nothing to hide")

    def test_short_secret_is_not_searched_for(self):
        # The built in default password is "gmp" and would otherwise match
        # logger names and other unrelated text
        register_secret("gmp")

        self.assertEqual(
            redact("gvm.protocols.gmp connected"), "gvm.protocols.gmp connected"
        )

    def test_password_in_xml_is_replaced(self):
        self.assertEqual(
            redact("<password>whatever</password>"),
            f"<password>{REDACTED}</password>",
        )

    def test_username_in_xml_is_replaced(self):
        self.assertEqual(
            redact("<username>whoever</username>"),
            f"<username>{REDACTED}</username>",
        )

    def test_mismatched_xml_tags_are_untouched(self):
        self.assertEqual(
            redact("<username>whoever</password>"),
            "<username>whoever</password>",
        )

    def test_credential_option_is_replaced(self):
        self.assertEqual(
            redact("--gmp-password=whatever"), f"--gmp-password={REDACTED}"
        )
        self.assertEqual(
            redact("--ssh-password whatever"), f"--ssh-password {REDACTED}"
        )
        self.assertEqual(
            redact("--ssh-username whoever"), f"--ssh-username {REDACTED}"
        )

    def test_non_string_is_returned_unchanged(self):
        register_secret(SECRET)

        self.assertEqual(redact(42), 42)

    def test_longest_secret_is_replaced_first(self):
        register_secret("secret")
        register_secret("secretary")

        self.assertEqual(redact("secretary"), REDACTED)


class RedactArgumentTokensTestCase(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_value_of_password_option_is_replaced(self):
        tokens = ["gvm-cli", "ssh", "--ssh-password", SECRET, "-X", "<x/>"]

        self.assertEqual(
            redact_argument_tokens(tokens),
            ["gvm-cli", "ssh", "--ssh-password", REDACTED, "-X", "<x/>"],
        )

    def test_value_of_username_option_is_replaced(self):
        # The user name is half of a credential and is exposed the same way
        tokens = ["gvm-cli", "--gmp-username", "scanadmin", "socket"]

        self.assertEqual(
            redact_argument_tokens(tokens),
            ["gvm-cli", "--gmp-username", REDACTED, "socket"],
        )

    def test_short_password_is_replaced_as_well(self):
        # Too short to be searched for, but its position is known
        tokens = ["--gmp-password", "gmp"]

        self.assertEqual(
            redact_argument_tokens(tokens), ["--gmp-password", "***"]
        )

    def test_result_is_never_longer_than_the_input(self):
        # The redacted command line is written back into the memory of the
        # process and must fit into the original. The kernel counts bytes,
        # so a password with umlauts is the interesting case.
        passwords = (
            "a",
            "gmp",
            "1234567",
            SECRET,
            "Pässwörtß",
            "äöü",
            "with spaces",
            r"a.*b[c]$d^e(f)|g+",
            "*" * 12,
            "L" * 200,
        )
        for password in passwords:
            with self.subTest(password=password):
                register_secret(password)
                tokens = ["gvm-cli", "--gmp-password", password]
                redacted = redact_argument_tokens(tokens)

                self.assertLessEqual(
                    len("\x00".join(redacted).encode()),
                    len("\x00".join(tokens).encode()),
                )
                self.assertNotIn(password, redacted[2])

    def test_trailing_empty_token_is_kept(self):
        # /proc/<pid>/cmdline ends with a NUL byte, which splits into an
        # empty last token that must not become a placeholder
        tokens = ["gvm-cli", "--gmp-password", ""]

        self.assertEqual(redact_argument_tokens(tokens)[-1], "")


class RedactedArgumentsTestCase(unittest.TestCase):
    def test_credential_arguments_are_replaced(self):
        args = Namespace(
            gmp_username="user",
            gmp_password="gmp",
            ssh_password=SECRET,
            hostname="127.0.0.1",
        )

        formatted = redacted_arguments(args)

        self.assertIn(f"gmp_username='{REDACTED}'", formatted)
        self.assertIn("hostname='127.0.0.1'", formatted)
        self.assertIn(f"gmp_password='{REDACTED}'", formatted)
        self.assertIn(f"ssh_password='{REDACTED}'", formatted)
        self.assertNotIn(SECRET, formatted)
        # short enough that only the structural replacement catches it
        self.assertNotIn("'gmp'", formatted)


class LogRedactionTestCase(unittest.TestCase):
    def setUp(self):
        clear_secrets()
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.logger = logging.getLogger("gvmtools.tests.secrets")
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

    def tearDown(self):
        clear_secrets()
        self.logger.removeHandler(self.handler)
        logging.setLogRecordFactory(logging.LogRecord)

    def test_secret_is_removed_from_message(self):
        install_log_redaction()
        register_secret(SECRET)

        self.logger.debug("connecting with %s", SECRET)

        self.assertNotIn(SECRET, self.stream.getvalue())
        self.assertIn(REDACTED, self.stream.getvalue())

    def test_secret_is_removed_from_dict_arguments(self):
        install_log_redaction()
        register_secret(SECRET)

        self.logger.debug("connecting with %(password)s", {"password": SECRET})

        self.assertNotIn(SECRET, self.stream.getvalue())

    def test_installing_twice_keeps_one_factory(self):
        install_log_redaction()
        factory = logging.getLogRecordFactory()

        install_log_redaction()

        self.assertIs(logging.getLogRecordFactory(), factory)


class PasswordFileTestCase(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_reads_password_without_trailing_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "password"
            file.write_text(f"{SECRET}\n", encoding="utf-8")
            file.chmod(0o600)

            self.assertEqual(read_password_file(str(file)), SECRET)

    def test_missing_file_raises(self):
        with self.assertRaises(RuntimeError):
            read_password_file("/does/not/exist")

    def test_dash_reads_from_stdin(self):
        with patch("sys.stdin", io.StringIO(f"{SECRET}\n")):
            self.assertEqual(read_password_file("-"), SECRET)


class ResolvePasswordTestCase(unittest.TestCase):
    def setUp(self):
        clear_secrets()

    def tearDown(self):
        clear_secrets()

    def test_prompt_wins(self):
        with patch("gvmtools.secrets.getpass.getpass", return_value=SECRET):
            password = resolve_password(
                value="from-argument",
                password_file="/does/not/exist",
                prompt=True,
                prompt_text="Password: ",
            )

        self.assertEqual(password, SECRET)

    def test_file_wins_over_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "password"
            file.write_text(SECRET, encoding="utf-8")
            file.chmod(0o600)

            password = resolve_password(
                value="from-argument",
                password_file=str(file),
                prompt=False,
                prompt_text="Password: ",
            )

        self.assertEqual(password, SECRET)

    def test_argument_is_the_fallback(self):
        password = resolve_password(
            value=SECRET,
            password_file=None,
            prompt=False,
            prompt_text="Password: ",
        )

        self.assertEqual(password, SECRET)

    def test_resolved_password_is_registered_as_secret(self):
        resolve_password(
            value=SECRET,
            password_file=None,
            prompt=False,
            prompt_text="Password: ",
        )

        self.assertEqual(redact(f"got {SECRET}"), f"got {REDACTED}")


HIDE_SCRIPT = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from gvmtools.secrets import hide_command_line, register_secret

register_secret(sys.argv[3])
print(hide_command_line())
cmdline = Path("/proc/self/cmdline").read_bytes().decode()
# the script itself is one of the arguments, so flatten the newlines
print(cmdline.replace(chr(0), " ").replace(chr(10), " "))
"""

WINDOWS_HIDE_SCRIPT = """
import ctypes, sys
sys.path.insert(0, sys.argv[1])
from gvmtools.secrets import hide_command_line, register_secret

register_secret(sys.argv[3])
print(hide_command_line())
get_command_line = ctypes.windll.kernel32.GetCommandLineW
get_command_line.restype = ctypes.c_wchar_p
# GetCommandLineW returns the same buffer the task manager reads out of
# the process environment block
print(get_command_line().replace(chr(10), " "))
"""


@unittest.skipUnless(
    sys.platform.startswith("linux"), "the command line is read from /proc"
)
class HideCommandLineTestCase(unittest.TestCase):
    def test_password_is_removed_from_the_command_line(self):
        root = str(Path(__file__).parent.parent)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                HIDE_SCRIPT,
                root,
                "--ssh-password",
                SECRET,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        hidden, cmdline = result.stdout.splitlines()[:2]

        self.assertEqual(hidden, "True")
        self.assertNotIn(SECRET, cmdline)
        self.assertIn(REDACTED, cmdline)
        # the rest of the command line survives
        self.assertIn("--ssh-password", cmdline)


@unittest.skipUnless(
    sys.platform == "win32", "the command line is read from the PEB"
)
class HideWindowsCommandLineTestCase(unittest.TestCase):
    def test_password_is_removed_from_the_command_line(self):
        root = str(Path(__file__).parent.parent)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                WINDOWS_HIDE_SCRIPT,
                root,
                "--ssh-password",
                SECRET,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        hidden, cmdline = result.stdout.splitlines()[:2]

        self.assertEqual(hidden, "True")
        self.assertNotIn(SECRET, cmdline)
        self.assertIn(REDACTED, cmdline)
        self.assertIn("--ssh-password", cmdline)


if __name__ == "__main__":
    unittest.main()
