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


def run_under_same_interpreter(script, args):
    print('\n** running: {}...'.format(script), file=sys.stderr)
    assert isinstance(script, str)
    assert path.abspath(script) == script
    assert isinstance(args, list)
    if not os.access(script, os.R_OK | os.X_OK):
        print('WARNING: cannot read and execute: {!r}'.format(script),
            file=sys.stderr
        )
        return
    cmd = [sys.executable, script] + args
    print('check_call:', cmd, file=sys.stderr)
    subprocess.check_call(cmd)
    print('** PASSED: {}\n'.format(script), file=sys.stderr)


def run_sphinx_doctest():
    script = '/usr/share/sphinx/scripts/python3/sphinx-build'
    doc = path.join(TREE, 'doc')
    doctest = path.join(TREE, 'doc', '_build', 'doctest')
    args = ['-EW', '-b', 'doctest', doc, doctest]
    run_under_same_interpreter(script, args)


def run_pyflakes3():
    script = '/usr/bin/pyflakes3'
    names = [
        'degu',
        'setup.py',
        'benchmark.py',
        'benchmark-parsing.py',
        'benchmark-ssl.py',
        'run-echo-app.py',
    ]
    args = [path.join(TREE, name) for name in names]
    run_under_same_interpreter(script, args)


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

