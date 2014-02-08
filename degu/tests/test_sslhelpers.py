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
from degu.sslhelpers import random_id
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

        # bits=2048
        sizes = [1671, 1675, 1679]
        sslhelpers.create_key(key, bits=2048)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

        # bits=3072
        sizes = [2455, 2459]
        sslhelpers.create_key(key, bits=3072)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

        # bits=4096 (default)
        sizes = [3239, 3243, 3247]
        sslhelpers.create_key(key)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)
        sslhelpers.create_key(key, bits=4096)
        self.assertLess(min(sizes) - 25, path.getsize(key))
        self.assertLess(path.getsize(key), max(sizes) + 25)
        os.remove(key)

    def test_create_ca(self):
        tmp = TempDir()
        foo_key = tmp.join('foo.key')
        foo_ca = tmp.join('foo.ca')
        sslhelpers.create_key(foo_key, bits=1024)
        self.assertFalse(path.exists(foo_ca))
        sslhelpers.create_ca(foo_key, '/CN=foo', foo_ca)
        self.assertGreater(path.getsize(foo_ca), 0)

    def test_create_csr(self):
        tmp = TempDir()
        bar_key = tmp.join('bar.key')
        bar_csr = tmp.join('bar.csr')
        sslhelpers.create_key(bar_key, bits=1024)
        self.assertFalse(path.exists(bar_csr))
        sslhelpers.create_csr(bar_key, '/CN=bar', bar_csr)
        self.assertGreater(path.getsize(bar_csr), 0)

    def test_issue_cert(self):
        tmp = TempDir()

        foo_key = tmp.join('foo.key')
        foo_ca = tmp.join('foo.ca')
        foo_srl = tmp.join('foo.srl')
        sslhelpers.create_key(foo_key, bits=1024)
        sslhelpers.create_ca(foo_key, '/CN=foo', foo_ca)

        bar_key = tmp.join('bar.key')
        bar_csr = tmp.join('bar.csr')
        bar_cert = tmp.join('bar.cert')
        sslhelpers.create_key(bar_key, bits=1024)
        sslhelpers.create_csr(bar_key, '/CN=bar', bar_csr)

        files = (foo_srl, bar_cert)
        for f in files:
            self.assertFalse(path.exists(f))
        sslhelpers.issue_cert(bar_csr, foo_ca, foo_key, foo_srl, bar_cert)
        for f in files:
            self.assertGreater(path.getsize(f), 0)

    def test_get_pubkey(self):
        tmp = TempDir()

        # Create CA
        foo_key = tmp.join('foo.key')
        foo_ca = tmp.join('foo.ca')
        foo_srl = tmp.join('foo.srl')
        sslhelpers.create_key(foo_key, bits=1024)
        foo_pubkey = sslhelpers.get_rsa_pubkey(foo_key)
        sslhelpers.create_ca(foo_key, '/CN=foo', foo_ca)

        # Create CSR and issue cert
        bar_key = tmp.join('bar.key')
        bar_csr = tmp.join('bar.csr')
        bar_cert = tmp.join('bar.cert')
        sslhelpers.create_key(bar_key, bits=1024)
        bar_pubkey = sslhelpers.get_rsa_pubkey(bar_key)
        sslhelpers.create_csr(bar_key, '/CN=bar', bar_csr)
        sslhelpers.issue_cert(bar_csr, foo_ca, foo_key, foo_srl, bar_cert)

        # Now compare
        os.remove(foo_key)
        os.remove(bar_key)
        self.assertEqual(sslhelpers.get_pubkey(foo_ca), foo_pubkey)
        self.assertEqual(sslhelpers.get_csr_pubkey(bar_csr), bar_pubkey)
        self.assertEqual(sslhelpers.get_pubkey(bar_cert), bar_pubkey)


class TestPKI(TestCase):
    def test_init(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        self.assertIs(pki.ssldir, tmp.dir)
        self.assertEqual(pki.tmpdir, tmp.join('tmp'))

        # Test when tmpdir already exists
        pki = sslhelpers.PKI(tmp.dir)

    def test_random_tmp(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        filename = pki.random_tmp()
        self.assertEqual(path.dirname(filename), tmp.join('tmp'))
        self.assertEqual(len(path.basename(filename)), 24)

    def test_path(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        cert_id = random_id(25)
        self.assertEqual(
            pki.path(cert_id, 'key'),
            tmp.join(cert_id + '.key')
        )
        self.assertEqual(
            pki.path(cert_id, 'cert'),
            tmp.join(cert_id + '.cert')
        )
        self.assertEqual(
            pki.path(cert_id, 'srl'),
            tmp.join(cert_id + '.srl')
        )

    def test_create_key(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        _id = pki.create_key(bits=1024)
        self.assertEqual(os.listdir(pki.tmpdir), [])
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set(['tmp', _id + '.key'])
        )
        key_file = path.join(pki.ssldir, _id + '.key')
        data = sslhelpers.get_rsa_pubkey(key_file)
        self.assertEqual(_id, sslhelpers.hash_pubkey(data))

    def test_create_ca(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        _id = pki.create_key(bits=1024)
        ca_file = tmp.join(_id + '.ca')
        self.assertFalse(path.exists(ca_file))
        self.assertEqual(pki.create_ca(_id), ca_file)
        self.assertTrue(path.isfile(ca_file))
        self.assertEqual(os.listdir(pki.tmpdir), [])
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set(['tmp', _id + '.key', _id + '.ca'])
        )

    def test_create_csr(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        _id = pki.create_key(bits=1024)
        csr_file = tmp.join(_id + '.csr')
        self.assertFalse(path.exists(csr_file))
        self.assertEqual(pki.create_csr(_id), csr_file)
        self.assertTrue(path.isfile(csr_file))
        self.assertEqual(os.listdir(pki.tmpdir), [])
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set(['tmp', _id + '.key', _id + '.csr'])
        )

    def test_issue_cert(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)

        # Create the CA
        ca_id = pki.create_key(bits=1024)
        pki.create_ca(ca_id)

        # Create the CSR
        cert_id = pki.create_key(bits=1024)
        pki.create_csr(cert_id)
        os.remove(tmp.join(cert_id + '.key'))

        # Now test
        cert_file = tmp.join(cert_id + '.cert')
        self.assertFalse(path.exists(cert_file))
        self.assertEqual(pki.issue_cert(cert_id, ca_id), cert_file)
        self.assertGreater(path.getsize(cert_file), 0)
        self.assertEqual(os.listdir(pki.tmpdir), [])
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set([
                'tmp',
                ca_id + '.key',
                ca_id + '.ca',
                ca_id + '.srl',
                cert_id + '.csr',
                cert_id + '.cert',
            ])
        )

    def test_get_server_config(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        server_id = random_id()
        self.assertEqual(pki.get_server_config(server_id), {
            'cert_file': pki.path(server_id, 'cert'),
            'key_file': pki.path(server_id, 'key'),
        })
        ca_id = random_id()
        self.assertEqual(pki.get_server_config(server_id, client_ca_id=ca_id), {
            'cert_file': pki.path(server_id, 'cert'),
            'key_file': pki.path(server_id, 'key'),
            'ca_file': pki.path(ca_id, 'ca'),
        })

    def test_get_client_config(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        ca_id = random_id()
        self.assertEqual(pki.get_client_config(ca_id), {
            'ca_file': pki.path(ca_id, 'ca'),
            'check_hostname': False,
        })
        client_id = random_id()
        self.assertEqual(pki.get_client_config(ca_id, client_id=client_id), {
            'ca_file': pki.path(ca_id, 'ca'),
            'check_hostname': False,
            'cert_file': pki.path(client_id, 'cert'),
            'key_file': pki.path(client_id, 'key'),
        })
