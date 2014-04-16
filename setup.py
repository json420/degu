#!/usr/bin/env python3

# degu: an embedded HTTP server and client library
# Copyright (C) 2014 Novacut Inc
#
# This file is part of `degu`.
#
# `degu` is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# `degu` is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with `degu`.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Jason Gerard DeRose <jderose@novacut.com>

"""
Install `degu`.
"""

import sys
if sys.version_info < (3, 4):
    sys.exit('ERROR: degu requires Python 3.4 or newer')

import os
from os import path
import subprocess
from distutils.core import setup
from distutils.cmd import Command

import degu
from degu.tests.run import run_tests


TREE = path.dirname(__file__)


def run_sphinx_doctest():
    sphinx_build = '/usr/share/sphinx/scripts/python3/sphinx-build'
    if not os.access(sphinx_build, os.R_OK | os.X_OK):
        print('warning, cannot read and execute: {!r}'.format(sphinx_build))
        return
    doc = path.join(TREE, 'doc')
    doctest = path.join(TREE, 'doc', '_build', 'doctest')
    cmd = [sys.executable, sphinx_build, '-EW', '-b', 'doctest', doc, doctest]
    subprocess.check_call(cmd)


def run_pyflakes3():
    pyflakes3 = '/usr/bin/pyflakes3'
    if not os.access(pyflakes3, os.R_OK | os.X_OK):
        print('WARNING: cannot read and execute: {!r}'.format(pyflakes3))
        return
    cmd = [pyflakes3, path.join(TREE, 'degu')]
    subprocess.check_call(cmd)


class Test(Command):
    description = 'run unit tests and doc tests'

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        if not run_tests():
            raise SystemExit('2')
        run_sphinx_doctest()
        run_pyflakes3()


setup(
    name='degu',
    description='an embedded HTTP server and client library',
    url='https://launchpad.net/degu',
    version=degu.__version__,
    author='Jason Gerard DeRose',
    author_email='jderose@novacut.com',
    license='LGPLv3+',
    packages=[
        'degu',
        'degu.tests',
    ],
    cmdclass={
        'test': Test,
    },
)
