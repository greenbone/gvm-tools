# -*- coding: utf-8 -*-
# Copyright (C) 2018-2021 Greenbone Networks GmbH
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
"""
Main module of gvm-tools.
"""


def get_version() -> str:
    """Returns the version of gvm-tools as a string in `PEP440`_ compliant
    format.

    Returns:
        str: Current version of gvm-tools

    .. _PEP440:
       https://www.python.org/dev/peps/pep-0440
    """
    # pylint: disable=import-outside-toplevel
    from .__version__ import __version__

    return __version__
