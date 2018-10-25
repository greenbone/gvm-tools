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
"""
Module for transforming responses
"""
from lxml import etree

from gmp.error import GmpError


class EtreeTransform:
    """
    Transform a response into a lxml.etree root element
    """

    def __init__(self):
        self._parser = etree.XMLParser(encoding='utf-8', recover=True)

    def _convert_response(self, response):
        return etree.XML(response, parser=self._parser)

    def __call__(self, response):
        return self._convert_response(response)


def _check_command_status(root):
    status = root.attrib['status']
    status_text = root.attrib['status_text']

    if status is None or status[0] != '2':
        raise GmpError('Error in response. {0}'.format(status_text))


class CheckCommandTransform(EtreeTransform):
    """
    Check the response code of a response and raise GmpError if
    response was an error response
    """
    def __call__(self, response):
        root = self._convert_response(response)

        _check_command_status(root)

        return response


class EtreeCheckCommandTransform(EtreeTransform):
    """
    Transform a response into a lxml.etree root element and raise GmpError if
    response was an error response
    """

    def __call__(self, response):
        root = self._convert_response(response)

        _check_command_status(root)

        return root
