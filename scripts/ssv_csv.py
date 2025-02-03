#!/usr/bin/env python3
# coding: utf-8
# -
# Copyright © 2015, 2017, 2020, 2022
#       mirabilos <t.glaser@tarent.de>
# Licensor: tarent solutions GmbH
#
# Provided that these terms and disclaimer and all copyright notices
# are retained or reproduced in an accompanying document, permission
# is granted to deal in this work without restriction, including un‐
# limited rights to use, publicly perform, distribute, sell, modify,
# merge, give away, or sublicence.
#
# This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to
# the utmost extent permitted by applicable law, neither express nor
# implied; without malicious intent or gross negligence. In no event
# may a licensor, author or contributor be held liable for indirect,
# direct, other damage, loss, or other issues arising in any way out
# of dealing in the work, even if advised of the possibility of such
# damage or existence of a defect, except proven that it results out
# of said person’s immediate fault when using the work as intended.

r"""SSV reader/writer and CSV writer library

This module offers the following classes:

- CSVInvalidCharacterError, CSVShapeError -- Exception classes
  that can be thrown by code from this library

- CSVPrinter -- configurable CSV row formatter and writer that
  ensures the output is quoted properly and in rectangular shape

- SSVPrinter -- CSVPrinter configured to produce SSV output

- CSVWriter, SSVWriter -- same but writing to a file-like object

- SSVReader -- class to read SSV files, returning lists of str|bytes
  (depending on the input file binary flag)

When run directly, it acts as SSV to CSV converter, which may be of
limited use but demonstrates how to use the module somewhat; -h for
usage (help).
"""

__all__ = [
    "CSVInvalidCharacterError",
    "CSVPrinter",
    "CSVShapeError",
    "CSVWriter",
    "SSVPrinter",
    "SSVReader",
    "SSVWriter",
]

import re
import sys
from typing import IO, AnyStr, List, Optional, TextIO


class CSVShapeError(Exception):
    r"""Error: data to write did not have a consistent amount of columns.

    The message string is descriptive, but the want and got fields of
    an object may be user-accessed.
    """

    def __init__(self, want: int, got: int) -> None:
        Exception.__init__(
            self, f"got {got} column{got != 1 and 's' or ''} but wanted {want}"
        )
        self.want = want  # type: int
        self.got = got  # type: int


class CSVInvalidCharacterError(Exception):
    r"""Error: disallowed characters in cell (writer) / row (reader).

    The message is deliberately constant in order to not show the actual
    cell or row content in logs, etc. (in case it’s a password) but the
    actual content is available in the questionable_content field.
    """

    def __init__(
        self, value: AnyStr, what: str = "prohibited character in cell"
    ) -> None:
        Exception.__init__(self, what)
        self.questionable_content = value  # type: Union[str, bytes]


class CSVPrinter(object):
    r"""CSV writer library, configurable.

    The defaults follow RFC 4180 and thus are suitable for use with most
    environments; newlines embedded in cell data are normalised (from
    ASCII/Unix/Mac to ASCII) by default, every cell data is quoted.

    The following arguments configure the writer instance:
    - sep -- output cell separator: ',' (default) or ';' or '\t'
    - quot -- output quote character (default '"'), escape by doubling;
        None to disable quoting and disallow embedded newlines (but not
        double quotes; the caller must not pass any if the result needs
        to conform to the RFC or just use default quoting of course)
    - eol -- output line terminator: '\r\n' or (Unix) '\n' or (Mac) '\r'
    - qnl -- output embedded newline, should match eol (default '\r\n');
        None to disable embedded newline normalisation

    These arguments must all be str, bytes is not supported. Cell data
    passed in that is not str will be stringified. Rows are written or
    returned as str; however, ASCII or a compatible encoding needs to
    be used (for conformance and portability); UTF-8 is ideal.

    Note: RFC 4180 permits only printable ASCII and space and, if quoted,
    newlines in cell data but this library permits any character except
    NUL, (unquoted) CR and LF.
    """

    # embedded NUL is never permitted
    _invf = re.compile("[\x00]")  # type: Pattern[str]
    # normalise embedded newlines (match)
    _nlf = re.compile("\r\n?|(?<!\r)\n")  # type: Pattern[str]
    # count to ensure rectangular shape of output
    _ncols = -1  # type: int

    # default line ending is ASCII (“DOS”)
    def __init__(
        self,
        sep: str = ",",
        quot: Optional[str] = '"',
        eol: str = "\r\n",
        qnl: Optional[str] = "\r\n",
    ) -> None:
        if quot is None:
            # cell joiner ('","')
            self._sep = sep  # type: str
            # one quote, e.g. for line beginning/end
            self._quots = ""  # type: str
            # two quotes to escape
            self._quotd = ""  # type: str
            # forbid newlines if we cannot quote them
            self._invf = re.compile("[\x00\r\n]")
        else:
            self._sep = quot + sep + quot
            self._quots = quot
            self._quotd = quot + quot
        # None if not quoting
        self._quot = quot  # type: Optional[str]
        # None or embedded newline replacement string
        self._nlrpl = qnl  # type: Optional[str]
        # EOL string
        self._eol = eol  # type: str

    def _mapcell(self, cell) -> str:
        if isinstance(cell, str):
            cstr = cell  # type: str
        else:
            cstr = str(cell)
        if self._invf.search(cstr) is not None:
            raise CSVInvalidCharacterError(cstr)
        if self._nlrpl is not None:
            cstr = self._nlf.sub(self._nlrpl, cstr)
        if self._quot is not None:
            cstr = cstr.replace(self._quots, self._quotd)
        return cstr

    def write(self, *args) -> None:
        r"""Print a CSV line (row) to standard output.

        - *args -- cell data by columns

        Note: reconfigures the newline mode of sys.stdout once,
        but make sure to run sys.stdout.reconfigure(newline='\n')
        e.g. when emitting an MS Excel sep= line and get the line
        ending for that right; see _main() for an example.
        """
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(newline="\n")  # type: ignore
        setattr(CSVPrinter, "write", getattr(CSVPrinter, "_write"))
        delattr(CSVPrinter, "_write")
        return self.write(*args)

    def _write(self, *args) -> None:
        print(self.format(*args), end="")

    _write.__doc__ = write.__doc__

    def format(self, *args) -> str:
        r"""Produce a CSV row from cells.

        - *args -- cell data by columns

        Returns the row, including the trailing newline, as string.
        """
        if self._ncols == -1:
            self._ncols = len(args)
        elif self._ncols != len(args):
            raise CSVShapeError(self._ncols, len(args))
        cells = map(self._mapcell, args)
        return self._quots + self._sep.join(cells) + self._quots + self._eol


class CSVWriter(CSVPrinter):
    r"""CSV writer library, configurable.

    The defaults follow RFC 4180 and thus are suitable for use with most
    environments; newlines embedded in cell data are normalised (from
    ASCII/Unix/Mac to ASCII) by default, every cell data is quoted.

    The following arguments configure the writer instance:
    - file -- file-like object to output CSV to
    - sep -- output cell separator: ',' (default) or ';' or '\t'
    - quot -- output quote character (default '"'), escape by doubling;
        None to disable quoting and disallow embedded newlines (but not
        double quotes; the caller must not pass any if the result needs
        to conform to the RFC or just use default quoting of course)
    - eol -- output line terminator: '\r\n' or (Unix) '\n' or (Mac) '\r'
    - qnl -- output embedded newline, should match eol (default '\r\n');
        None to disable embedded newline normalisation

    These arguments must all be str, bytes is not supported. Cell data
    passed in that is not str will be stringified. Rows are written or
    returned as str; however, ASCII or a compatible encoding needs to
    be used (for conformance and portability); UTF-8 is ideal.

    Note: RFC 4180 permits only printable ASCII and space and, if quoted,
    newlines in cell data but this library permits any character except
    NUL, (unquoted) CR and LF.

    Note: the file argument will be reconfigured to disable automatic
    '\n' conversion; if prepending data (e.g. a sep= line for MS Excel)
    use the writeln() method.
    """

    def __init__(
        self,
        file: TextIO,
        sep: str = ",",
        quot: Optional[str] = '"',
        eol: str = "\r\n",
        qnl: Optional[str] = "\r\n",
    ) -> None:
        CSVPrinter.__init__(self, sep, quot, eol, qnl)
        # disable any automatic newline conversion if preset
        file.reconfigure(newline="\n")  # type: ignore
        self.outfile = file

    def write(self, *args) -> None:
        r"""Print a CSV line (row) to the output file.

        - *args -- cell data by columns
        """
        print(self.format(*args), end="", file=self.outfile)

    def writeln(self, line: str) -> None:
        r"""Print an arbitrary nōn-CSV line to the output file.

        - line -- str to output; trailing newline is automatically added
        """
        print(line, end=self._eol, file=self.outfile)


class SSVPrinter(CSVPrinter):
    r"""SSV writer library.

    This subclass sets up a CSVPrinter instance to produce SSV (see below).
    The writer supports str, or stringified arguments, only, not bytes.
    The caller must ensure the encoding is UTF-8 (ideally), or at least
    ASCII-compatible (CR, LF and \x1F require identity mapping), and that
    CR or LF characters output are not converted.

    shell-parseable separated values (or separator-separated values)
    is an idea to make CSV into something usable:

    • newline (\x0A) is row separator
    • unit separator (\x1F) is column separator
    • n̲o̲ quotes or escape characters
    • carriage return (\x0D) represents embedded newlines in cells

    Cell content is, in theory, arbitrary binary except NUL and
    the separators (\x1F and \x0A). In practice it should be UTF-8.

    SSV can be easily read from shell scripts:

        while IFS=$'\x1F' read -r col1 col2…; do
            # do something
        done
    """

    def __init__(self) -> None:
        CSVPrinter.__init__(self, sep="\x1f", quot=None, eol="\n", qnl="\r")
        # not permitted in SSV data
        self._invf = re.compile("[\x00\x1f]")


class SSVWriter(CSVWriter):
    r"""SSV writer library (same as SSVPrinter except to file)"""

    def __init__(self, file: TextIO) -> None:
        # pylint: disable=C0301
        CSVWriter.__init__(
            self, file, sep="\x1f", quot=None, eol="\n", qnl="\r"
        )
        # not permitted in SSV data
        self._invf = re.compile("[\x00\x1f]")


if SSVPrinter.__doc__ is not None:
    SSVWriter.__doc__ = SSVPrinter.__doc__.replace("CSVPrinter", "CSVWriter")


class SSVReader(object):
    r"""SSV reader library.

    This library is initialised with a files-like object that must
    support .readline() and either must not use newline conversion
    or support .reconfigure() as in _io.TextIOWrapper, which is
    called with newline='\n' if it exists. SSVReader.read() will
    then proceed to read from it.

    See SSVPrinter about the SSV format.
    """

    def __init__(self, file: IO) -> None:
        if hasattr(file, "reconfigure"):
            # see https://bugs.python.org/issue46695 though
            file.reconfigure(newline="\n")  # type: ignore
        self.f = file  # type: IO

    @staticmethod
    def _read(
        line: AnyStr,
        lf: AnyStr,
        cr: AnyStr,
        us: AnyStr,
        nl: AnyStr,
        nul: AnyStr,
    ) -> List[AnyStr]:
        if line.find(nul) != -1:
            raise CSVInvalidCharacterError(line, "NUL in row")
        if line[-1:] != lf:
            raise CSVInvalidCharacterError(line, "unterminated row")
        line = line[:-1]
        if line.find(lf) != -1:
            raise CSVInvalidCharacterError(line, "LF in row")
        return line.replace(cr, nl).split(us)

    def read(self) -> Optional[List[AnyStr]]:
        r"""Read and decode one SSV line.

        Returns a list of cells, or None on EOF.
        """
        line = self.f.readline()  # type: Optional[AnyStr]
        if not line:
            return None
        if isinstance(line, str):
            return self._read(line, "\n", "\r", "\x1f", "\r\n", "\x00")
        if isinstance(line, bytes):
            return self._read(line, b"\n", b"\r", b"\x1f", b"\r\n", b"\x00")
        raise TypeError()


# mostly example of how to use this
def _main() -> None:
    # pylint: disable=C0103
    newline_ways = {
        "ascii": "\r\n",
        "unix": "\n",
        "mac": "\r",
    }
    p = argparse.ArgumentParser(
        description="Converts SSV to CSV.",
        # part of https://bugs.python.org/issue46700 workaround
        add_help=False,
    )
    g = p.add_argument_group("Options")  # issue46700
    g.add_argument("-h", action="help", help="show this help message and exit")
    g.add_argument(
        "-s",
        metavar="sep",
        help="cell separator, e.g. \x27,\x27 (default: tab)",
        default="\t",
    )
    g.add_argument(
        "-q",
        metavar="qch",
        help="quote character, e.g. \x27\x22\x27 (default: none)",
        default=None,
    )
    g.add_argument(
        "-n",
        metavar="eoltype",
        choices=list(newline_ways.keys()),
        help="line endings (ascii (default), unix, mac)",
        default="ascii",
    )
    g.add_argument(
        "-P",
        metavar="preset",
        choices=["std", "sep", "ssv"],
        help="predefined config (std=RFC 4180, sep=Excel header, ssv=SSV)",
    )
    g = p.add_argument_group("Arguments")  # issue46700
    g.add_argument(
        "file",
        nargs="?",
        help='SSV file to read, "-" for stdin (default)',
        default="-",
    )
    args = p.parse_args()
    if args.P in ("std", "sep"):
        args.s = ","
        args.q = '"'
        args.n = "ascii"
    nl = newline_ways[args.n]
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(newline="\n")  # type: ignore
    if args.P == "sep":
        print(f"sep={args.s}", end=nl)
    if args.P != "ssv":
        w = CSVPrinter(args.s, args.q, nl, nl)
    else:
        w = SSVPrinter()

    def _convert(f):
        r = SSVReader(f)
        # no walrus in Python 3.7 yet ☹
        while True:
            row = r.read()
            if row is None:
                break
            w.write(*row)

    if args.file == "-":
        _convert(sys.stdin)
    else:
        with open(args.file, "r", encoding="utf-8") as file:
            _convert(file)


if __name__ == "__main__":
    import argparse

    _main()
