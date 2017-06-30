# -*- coding: utf-8 -*-
# Description:
# setup file for clients
#
# Authors:
# Raphael Grewe <raphael.grewe@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

"""A setuptools based setup module.
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'VERSION'), encoding='utf-8') as f:
    version = f.read()

setup(
    name='gvm-tools',
    version=version,
    description='Library and clients to speak with GVM over GMP or OSP',
    long_description=long_description,
    author='Raphael Grewe',
    author_email='raphael.grewe@greenbone.net',
    license='GPL v3',

    packages=find_packages(),
    install_requires=['paramiko', 'lxml'],
    entry_points={
        'console_scripts': [
            'gvm-pyshell=gmp.clients.gvm_pyshell:main',
            'gvm-cli=gmp.clients.gvm_cli:main',
            'gvm-dialog=gmp.clients.gvm_dialog:main',
        ],
    },
    data_files=[('', ['VERSION'])],
    package_data={
        '': ['VERSION']
    }
)
