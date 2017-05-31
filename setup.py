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

setup(
    name='gvm-tools',
    version='1.0',
    description='Library and clients to speak with GVM over GMP or OSP',
    long_description=long_description,
    author='Raphael Grewe',
    author_email='raphael.grewe@greenbone.net',
    license='GPL v3',

    packages=find_packages(),
    install_requires=['paramiko', 'lxml'],
    entry_points={
        'console_scripts': [
            'gvm-pyshell=clients.gvm_pyshell:main',
            'gvm-cli=clients.gvm_cli:main',
        ],
    },
)
