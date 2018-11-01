# -*- coding: utf-8 -*-
# Copyright (C) 2018 Greenbone Networks GmbH
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
"""Lastest supported protocols.

This module exposes the lastest supported protocols of gvm-tools.

The provided Gmp class implements the lastest `Greenbone Management
Protocol`_.

For details about the possible supported protocol versions please take a look at
:py:mod:`gmp.protocols`.

Exports:
  - :py:class:`gmp.protocols.gmpv7.Gmp`

.. _Greenbone Management Protocol:
    https://docs.greenbone.net/API/GMP/gmp.html
"""

from .gmpv7 import Gmp

__all__ = ['Gmp']
