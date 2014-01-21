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
Unit tests the `degu.sslhelpers` module.
"""

from unittest import TestCase
import os
from os import path

from .helpers import TempDir
from degu import sslhelpers


class TestSSLFunctions(TestCase):
    def test_create_key(self):
        tmp = TempDir()
        key = tmp.join('key.pem')

        # bits=1024
        sizes = [883, 887, 891]
        sslhelpers.create_key(key, bits=1024)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

        # bits=2048 (default)
        sizes = [1671, 1675, 1679]
        sslhelpers.create_key(key)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

        sslhelpers.create_key(key, bits=2048)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

        # bits=3072
        sizes = [2455, 2459]
        sslhelpers.create_key(key, bits=3072)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)

        # bits=4096
        sizes = [3239, 3243, 3247]
        sslhelpers.create_key(key, bits=4096)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)

    def test_create_ca(self):
        tmp = TempDir()
        foo_key = tmp.join('foo.key')
        foo_ca = tmp.join('foo.ca')
        sslhelpers.create_key(foo_key)
        self.assertFalse(path.exists(foo_ca))
        sslhelpers.create_ca(foo_key, '/CN=foo', foo_ca)
        self.assertGreater(path.getsize(foo_ca), 0)

    def test_create_csr(self):
        tmp = TempDir()
        bar_key = tmp.join('bar.key')
        bar_csr = tmp.join('bar.csr')
        sslhelpers.create_key(bar_key)
        self.assertFalse(path.exists(bar_csr))
        sslhelpers.create_csr(bar_key, '/CN=bar', bar_csr)
        self.assertGreater(path.getsize(bar_csr), 0)

    def test_issue_cert(self):
        tmp = TempDir()

        foo_key = tmp.join('foo.key')
        foo_ca = tmp.join('foo.ca')
        foo_srl = tmp.join('foo.srl')
        sslhelpers.create_key(foo_key)
        sslhelpers.create_ca(foo_key, '/CN=foo', foo_ca)

        bar_key = tmp.join('bar.key')
        bar_csr = tmp.join('bar.csr')
        bar_cert = tmp.join('bar.cert')
        sslhelpers.create_key(bar_key)
        sslhelpers.create_csr(bar_key, '/CN=bar', bar_csr)

        files = (foo_srl, bar_cert)
        for f in files:
            self.assertFalse(path.exists(f))
        sslhelpers.issue_cert(bar_csr, foo_ca, foo_key, foo_srl, bar_cert)
        for f in files:
            self.assertGreater(path.getsize(f), 0)
