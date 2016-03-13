# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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
        # 1024 bit:
        key_data = sslhelpers.create_key(1024)
        self.assertIn(len(key_data), [883, 887, 891])
        sslhelpers.get_pubkey(key_data)

        # 2048 bit:
        key_data = sslhelpers.create_key(2048)
        self.assertIn(len(key_data), [1671, 1675, 1679])
        sslhelpers.get_pubkey(key_data)

        # 3072 bit:
        key_data = sslhelpers.create_key(3072)
        self.assertIn(len(key_data), [2455, 2459])
        sslhelpers.get_pubkey(key_data)

        # 4096 bit:
        key_data = sslhelpers.create_key(4096)
        self.assertIn(len(key_data), [3239, 3243, 3247])
        sslhelpers.get_pubkey(key_data)

    def test_create_ca(self):
        key_data = sslhelpers.create_key(1024)
        pubkey_data = sslhelpers.get_pubkey(key_data)
        tmp = TempDir()
        key_file = tmp.write(key_data, 'foo.key')
        ca_data = sslhelpers.create_ca(key_file, '/CN=foo')
        self.assertEqual(sslhelpers.get_cert_pubkey(ca_data), pubkey_data)

    def test_create_csr(self):
        key = sslhelpers.create_key(1024)
        pubkey = sslhelpers.get_pubkey(key)
        tmp = TempDir()
        key_file = tmp.write(key, 'foo.key')
        csr = sslhelpers.create_csr(key_file, '/CN=foo')
        self.assertEqual(sslhelpers.get_csr_pubkey(csr), pubkey)

    def test_issue_cert(self):
        tmp = TempDir()

        foo_key_file = tmp.join('foo.key')
        foo_ca_file = tmp.join('foo.ca')
        foo_srl_file = tmp.join('foo.srl')
        foo_key = sslhelpers.create_key(1024)
        sslhelpers.safe_write(foo_key_file, foo_key)
        foo_ca = sslhelpers.create_ca(foo_key_file, '/CN=foo')
        sslhelpers.safe_write(foo_ca_file, foo_ca)

        bar_key_file = tmp.join('bar.key')
        bar_csr_file = tmp.join('bar.csr')
        bar_key = sslhelpers.create_key(1024)
        sslhelpers.safe_write(bar_key_file, bar_key)
        bar_csr = sslhelpers.create_csr(bar_key_file, '/CN=bar')
        sslhelpers.safe_write(bar_csr_file, bar_csr)

        bar_cert = sslhelpers.issue_cert(
            bar_csr_file, foo_ca_file, foo_key_file, foo_srl_file
        )
        self.assertEqual(
            sslhelpers.get_cert_pubkey(bar_cert),
            sslhelpers.get_pubkey(bar_key)
        )


class TestPKI(TestCase):
    def test_init(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        self.assertIs(pki.ssldir, tmp.dir)

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
        self.assertEqual(os.listdir(pki.ssldir), [ _id + '.key'])
        key_file = path.join(pki.ssldir, _id + '.key')
        key_data = open(key_file, 'rb').read()
        pubkey_data = sslhelpers.get_pubkey(key_data)
        self.assertEqual(_id, sslhelpers.hash_pubkey(pubkey_data))

    def test_create_ca(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        _id = pki.create_key(bits=1024)
        ca_file = tmp.join(_id + '.ca')
        self.assertFalse(path.exists(ca_file))
        self.assertEqual(pki.create_ca(_id), ca_file)
        self.assertTrue(path.isfile(ca_file))
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set([_id + '.key', _id + '.ca'])
        )

    def test_create_csr(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        _id = pki.create_key(bits=1024)
        csr_file = tmp.join(_id + '.csr')
        self.assertFalse(path.exists(csr_file))
        self.assertEqual(pki.create_csr(_id), csr_file)
        self.assertTrue(path.isfile(csr_file))
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set([_id + '.key', _id + '.csr'])
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
        self.assertEqual(
            set(os.listdir(pki.ssldir)),
            set([
                ca_id + '.key',
                ca_id + '.ca',
                ca_id + '.srl',
                cert_id + '.csr',
                cert_id + '.cert',
            ])
        )

    def test_get_server_sslconfig(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        server_id = random_id()
        ca_id = random_id()
        self.assertEqual(
            pki.get_server_sslconfig(server_id, ca_id),
            {
                'cert_file': pki.path(server_id, 'cert'),
                'key_file': pki.path(server_id, 'key'),
                'ca_file': pki.path(ca_id, 'ca'),
            }
        )

    def test_get_anonymous_server_sslconfig(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        server_id = random_id()
        self.assertEqual(
            pki.get_anonymous_server_sslconfig(server_id),
            {
                'cert_file': pki.path(server_id, 'cert'),
                'key_file': pki.path(server_id, 'key'),
                'allow_unauthenticated_clients': True,
            }
        )

    def test_get_client_sslconfig(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        ca_id = random_id()
        client_id = random_id()
        self.assertEqual(
            pki.get_client_sslconfig(ca_id, client_id),
            {
                'ca_file': pki.path(ca_id, 'ca'),
                'check_hostname': False,
                'cert_file': pki.path(client_id, 'cert'),
                'key_file': pki.path(client_id, 'key'),
            }
        )

    def test_get_anonymous_client_sslconfig(self):
        tmp = TempDir()
        pki = sslhelpers.PKI(tmp.dir)
        ca_id = random_id()
        self.assertEqual(
            pki.get_anonymous_client_sslconfig(ca_id),
            {
                'ca_file': pki.path(ca_id, 'ca'),
                'check_hostname': False,
            }
        )

