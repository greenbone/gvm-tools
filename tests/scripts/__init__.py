# -*- coding: utf-8 -*-
# Copyright (C) 2020-2022 Greenbone AG
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

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Union
from unittest.mock import MagicMock, create_autospec

from gvm.protocols.latest import Gmp
from lxml import etree


def load_script(path: Union[str, Path], script_name: str):
    """loading a script for a test case"""
    spec = spec_from_file_location(
        script_name, f"{str(path)}/{script_name}.gmp.py"
    )
    script = module_from_spec(spec)
    spec.loader.exec_module(script)

    return script


class GmpMockFactory:
    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        gmp_protocol_mock = create_autospec(Gmp)

        self.gmp_protocol = gmp_protocol_mock
        self.gmp = MagicMock()
        self.gmp.is_authenticated = MagicMock(return_value=True)
        self.gmp_protocol.types = MagicMock()
        self.gmp.__enter__.return_value = gmp_protocol_mock

    def __call__(self, *args, **kwargs):
        return self.gmp

    def mock_response(self, request_name: str, content: str):
        func = getattr(self.gmp_protocol, request_name)
        func.return_value = etree.fromstring(content)

    def mock_responses(self, request_name: str, content: str):
        func = getattr(self.gmp_protocol, request_name)
        func.side_effect = [etree.fromstring(c) for c in content]
