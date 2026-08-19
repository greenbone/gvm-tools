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

"""Keep credentials out of the process list and out of log files.

A credential that is passed as ``--ssh-password``, ``--gmp-password`` or one
of the matching ``--*-username`` options ends up in two places where it does
not belong:

* in the command line of the running process, which is world readable on
  Linux (``ps``, ``/proc/<pid>/cmdline``) and shown by the Windows task
  manager and by WMI (``Win32_Process.CommandLine``),
* in the log file, because the parsed arguments are written there with
  ``--log DEBUG``.

This module addresses both. The reliable fix is to never put the secret on
the command line in the first place -- see :func:`resolve_password` for the
supported alternatives. For the case where a credential *was* passed on the
command line, :func:`hide_command_line` overwrites it in place so that it is
no longer visible to other processes. That works on Linux, where the kernel
reads the command line out of the memory of the process, and on Windows,
where the task manager reads it out of the process environment block.
"""

import ctypes
import getpass
import logging
import os
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

REDACTED = "********"

#: Secrets shorter than this are not searched for in arbitrary strings. A
#: short secret (the built in default password is ``gmp``) would otherwise
#: match unrelated text and mangle the log output.
MIN_SEARCHABLE_SECRET_LENGTH = 6

_secrets: set[str] = set()

#: Options whose value is a credential. Used to redact a command line
#: without having to know the value itself. The user name is part of a
#: credential, so it is treated the same way as the password.
PASSWORD_OPTIONS = ("--ssh-password", "--gmp-password")
USERNAME_OPTIONS = ("--ssh-username", "--gmp-username")
CREDENTIAL_OPTIONS = PASSWORD_OPTIONS + USERNAME_OPTIONS

_XML_CREDENTIAL_RE = re.compile(
    r"(<(password|username)[^>]*>)(.*?)(</\2>)", re.IGNORECASE | re.DOTALL
)
_INLINE_CREDENTIAL_RE = re.compile(
    r"(--(?:ssh|gmp)-(?:password|username)[=\s]+)(\"[^\"]*\"|\S+)",
    re.IGNORECASE,
)


def register_secret(secret: str | None) -> None:
    """Mark a value as a secret

    Registered secrets are removed from log records and from the process
    command line.
    """
    if secret:
        _secrets.add(str(secret))


def clear_secrets() -> None:
    """Forget all registered secrets. Only used by the tests."""
    _secrets.clear()


def _mask_for(value: str, preserve_length: bool) -> str:
    """Placeholder for *value*

    When the result is written back into the command line it must not be
    longer than what it replaces, otherwise the memory of the neighbouring
    argument would be overwritten.
    """
    if preserve_length and len(value) < len(REDACTED):
        return "*" * len(value)
    return REDACTED


def redact(text: str, *, preserve_length: bool = False) -> str:
    """Replace every known secret in *text* with a placeholder

    Besides the registered secrets this also masks user names and passwords
    in GMP XML payloads and in ``--gmp-password=`` style arguments, because
    those carry credentials even when the value was never registered.
    """
    if not isinstance(text, str):
        return text

    # Longest first, so that a secret that contains another one is replaced
    # as a whole.
    for secret in sorted(_secrets, key=len, reverse=True):
        if len(secret) >= MIN_SEARCHABLE_SECRET_LENGTH and secret in text:
            text = text.replace(secret, _mask_for(secret, preserve_length))

    text = _XML_CREDENTIAL_RE.sub(
        lambda match: (
            match.group(1)
            + _mask_for(match.group(3), preserve_length)
            + match.group(4)
        ),
        text,
    )
    return _INLINE_CREDENTIAL_RE.sub(
        lambda match: (
            match.group(1) + _mask_for(match.group(2), preserve_length)
        ),
        text,
    )


#: Parts of an argument name that mark its value as a credential
CREDENTIAL_ARGUMENTS = ("password", "username", "secret")


def redacted_arguments(args) -> str:
    """Format parsed arguments for logging without exposing credentials

    Every argument whose name looks like a credential is replaced by a
    placeholder. This is a structural replacement and therefore also covers
    values that are too short to be searched for by :func:`redact`.
    """
    values = []
    for name, value in sorted(vars(args).items()):
        is_credential = value and any(
            part in name for part in CREDENTIAL_ARGUMENTS
        )
        shown = REDACTED if is_credential else value
        values.append(f"{name}={shown!r}")
    return f"Namespace({', '.join(values)})"


class _RedactingRecordFactory:
    """Log record factory that removes secrets from every record"""

    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __call__(self, *args, **kwargs):
        record = self.wrapped(*args, **kwargs)

        if not _secrets:
            return record

        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: redact(value) if isinstance(value, str) else value
                    for key, value in record.args.items()
                }
            else:
                record.args = tuple(
                    redact(value) if isinstance(value, str) else value
                    for value in record.args
                )
        return record


def install_log_redaction() -> None:
    """Remove secrets from all log records of the current process

    Hooking into the record factory covers every logger and every handler,
    including the loggers of python-gvm and paramiko and handlers that are
    added later on.
    """
    factory = logging.getLogRecordFactory()

    if isinstance(factory, _RedactingRecordFactory):
        return

    logging.setLogRecordFactory(_RedactingRecordFactory(factory))


def redact_argument_tokens(tokens: list[str]) -> list[str]:
    """Redact a command line that is available as separate arguments

    The value of a credential option is replaced regardless of its content,
    so this also covers values that are too short for :func:`redact`.
    """
    redacted = []
    mask_next = False

    for token in tokens:
        if mask_next and token:
            redacted.append(_mask_for(token, preserve_length=True))
            mask_next = False
            continue
        mask_next = token in CREDENTIAL_OPTIONS
        redacted.append(redact(token, preserve_length=True))

    return redacted


def _hide_command_line_linux(redacted: bytes, raw: bytes) -> bool:
    """Overwrite the argument vector of the running process

    The kernel builds ``/proc/<pid>/cmdline`` from the memory range
    ``[arg_start, arg_end)`` of the process, which lies in our own address
    space and is writable. The replacement must not be longer than the
    original, the remainder is padded with NUL bytes.
    """
    start, size = _linux_argv_range()

    if start is None or size != len(raw):
        return False

    # Only write when the memory really is the command line we read. This
    # guards against a relocated environment block and against a mismatch
    # between /proc and the actual layout.
    if ctypes.string_at(start, size) != raw:
        return False

    ctypes.memmove(start, redacted.ljust(size, b"\x00"), size)
    return True


def _linux_argv_range() -> tuple[int | None, int]:
    """Locate the argument vector of the running process in memory"""
    # /proc/self/stat exposes arg_start and arg_end directly. The comm field
    # is enclosed in parentheses and may itself contain spaces.
    try:
        stat = Path("/proc/self/stat").read_bytes()
        fields = stat[stat.rindex(b")") + 2 :].split()
        arg_start = int(fields[45])
        arg_end = int(fields[46])
        if arg_start and arg_end > arg_start:
            return arg_start, arg_end - arg_start
    except (OSError, ValueError, IndexError):
        logger.debug("Could not read the argument vector from /proc/self/stat")

    # Fall back to the environment block, which directly follows the
    # arguments on the stack.
    try:
        libc = ctypes.CDLL(None)
        environ = ctypes.POINTER(ctypes.c_char_p).in_dll(libc, "environ")
        first_env = ctypes.cast(
            ctypes.addressof(environ.contents), ctypes.POINTER(ctypes.c_void_p)
        )[0]
        size = len(Path("/proc/self/cmdline").read_bytes())
        return first_env - size, size
    except (OSError, ValueError, AttributeError):
        logger.debug("Could not locate the argument vector via environ")

    return None, 0


def _hide_command_line_windows(redacted: str) -> bool:
    """Overwrite the command line in the process environment block

    The task manager and ``Win32_Process.CommandLine`` do not remember the
    command line themselves, they read it out of the PEB of the process. So
    patching our own PEB removes the password from both. The replacement is
    padded with spaces because Windows treats the string as a whole.
    """

    class _UnicodeString(ctypes.Structure):
        _fields_ = (
            ("Length", ctypes.c_ushort),
            ("MaximumLength", ctypes.c_ushort),
            ("Buffer", ctypes.c_void_p),
        )

    class _ProcessBasicInformation(ctypes.Structure):
        _fields_ = (
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_void_p),
            ("Reserved3", ctypes.c_void_p),
        )

    is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
    # Offset of ProcessParameters inside the PEB and of CommandLine inside
    # RTL_USER_PROCESS_PARAMETERS. Stable across the supported Windows
    # versions, but verified against the actual content below.
    parameters_offset = 0x20 if is_64bit else 0x10
    command_line_offset = 0x70 if is_64bit else 0x40

    try:
        ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined]
        information = _ProcessBasicInformation()
        status = ntdll.NtQueryInformationProcess(
            ctypes.c_void_p(-1),  # pseudo handle of the current process
            0,  # ProcessBasicInformation
            ctypes.byref(information),
            ctypes.sizeof(information),
            None,
        )
        if status != 0 or not information.PebBaseAddress:
            return False

        parameters = ctypes.c_void_p.from_address(
            information.PebBaseAddress + parameters_offset
        ).value
        if not parameters:
            return False

        command_line = _UnicodeString.from_address(
            parameters + command_line_offset
        )
        if not command_line.Buffer or not command_line.Length:
            return False

        current = ctypes.wstring_at(
            command_line.Buffer, command_line.Length // 2
        )
        # If this is not the command line we expect, the offsets do not match
        # this Windows version and we must not write anything.
        if sys.argv and sys.argv[-1] not in current:
            return False

        # Write exactly as many characters as the original had, so the
        # buffer cannot overflow. The padding keeps Length valid.
        padded = redacted[: len(current)].ljust(len(current))
        buffer = ctypes.create_unicode_buffer(padded, len(current) + 1)
        ctypes.memmove(
            command_line.Buffer,
            buffer,
            len(current) * ctypes.sizeof(ctypes.c_wchar),
        )
        return True
    except (OSError, ValueError, AttributeError):
        logger.debug("Could not patch the command line in the PEB")
        return False


def hide_command_line() -> bool:
    """Remove the registered secrets from the command line of this process

    Returns ``True`` when the command line no longer contains a secret,
    either because it never did or because it could be overwritten.
    """
    if not _secrets:
        return True

    if sys.platform.startswith("linux"):
        try:
            raw = Path("/proc/self/cmdline").read_bytes()
        except OSError:
            return False

        tokens = raw.decode("utf-8", errors="surrogateescape").split("\x00")
        redacted = "\x00".join(redact_argument_tokens(tokens)).encode(
            "utf-8", errors="surrogateescape"
        )

        if redacted == raw:
            return True
        if len(redacted) > len(raw):  # pragma: no cover - redaction shortens
            return False

        return _hide_command_line_linux(redacted, raw)

    if sys.platform == "win32":
        get_command_line = ctypes.windll.kernel32.GetCommandLineW  # type: ignore[attr-defined]
        get_command_line.restype = ctypes.c_wchar_p
        current = get_command_line()
        redacted = redact(current, preserve_length=True)

        if redacted == current:
            return True

        return _hide_command_line_windows(redacted)

    return False


def read_password_file(path: str) -> str:
    """Read a password from a file

    A single dash reads from standard input, which allows piping a password
    in without it ever reaching the command line or the file system.
    """
    if path == "-":
        return sys.stdin.readline().rstrip("\r\n")

    file = Path(path).expanduser()

    try:
        mode = file.stat().st_mode
    except OSError as e:
        raise RuntimeError(
            f"Could not read password file {path}. {e}"
        ) from None

    if os.name == "posix" and mode & 0o077:
        logger.warning(
            "Password file %s is readable by other users. Restrict it with "
            "chmod 600.",
            path,
        )

    try:
        # A trailing newline is part of the file, not of the password.
        return file.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as e:
        raise RuntimeError(
            f"Could not read password file {path}. {e}"
        ) from None


def resolve_password(
    *,
    value: str | None,
    password_file: str | None,
    prompt: bool,
    prompt_text: str,
) -> str | None:
    """Determine a password from the sources that do not leak it

    The sources are tried in this order, the first one that yields a value
    wins:

    1. ``--...-password-prompt``, which asks on the terminal,
    2. ``--...-password-file``, a file or ``-`` for standard input,
    3. ``--...-password``, which defaults to the environment variable and
       then to the configuration file.

    The returned value is registered as a secret so that it is removed from
    the log output even when it was read from a file.
    """
    if prompt:
        password = getpass.getpass(prompt_text)
    elif password_file:
        password = read_password_file(password_file)
    else:
        password = value

    register_secret(password)
    return password
