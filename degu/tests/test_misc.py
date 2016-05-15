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
Unit tests the `degu.misc` module.
"""

from unittest import TestCase
from os import path

from degu.server import Request
from degu import misc


class TestFunctions(TestCase):
    def test_mkreq(self):
        r = misc.mkreq('GET', '/')
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)

        r = misc.mkreq('GET', '/?')
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/?')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(r.query, '')

        r = misc.mkreq('GET', '/?key=val')
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/?key=val')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(r.query, 'key=val')

        r = misc.mkreq('GET', '/foo/bar')
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo/bar')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo', 'bar'])
        self.assertIsNone(r.query)

        # shift=1:
        r = misc.mkreq('GET', '/foo/bar', shift=1)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo/bar')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, ['bar'])
        self.assertIsNone(r.query)

        # shift=2:
        r = misc.mkreq('GET', '/foo/bar', shift=2)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo/bar')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, ['foo', 'bar'])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)

        # With headers:
        headers = {'content-length': 32}
        r = misc.mkreq('GET', '/', headers)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertIs(r.headers, headers)
        self.assertEqual(r.headers, {'content-length': 32})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)

        # With body:
        body = 'my body'
        r = misc.mkreq('GET', '/', headers, body)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertIs(r.headers, headers)
        self.assertEqual(r.headers, {'content-length': 32})
        self.assertIs(r.body, body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)


class TestTempPKI(TestCase):
    def test_init(self):
        # Test when client_pki=True:
        pki = misc.TempPKI()
        self.assertGreater(path.getsize(pki.path(pki.server_ca_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_ca_id, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_id, 'cert')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_ca_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_ca_id, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_id, 'cert')), 0)

        # pki.server_sslconfig property:
        self.assertEqual(pki.server_sslconfig, {
            'cert_file': pki.path(pki.server_id, 'cert'),
            'key_file': pki.path(pki.server_id, 'key'),
            'ca_file': pki.path(pki.client_ca_id, 'ca'),
        })

        self.assertEqual(pki.anonymous_server_sslconfig, {
            'cert_file': pki.path(pki.server_id, 'cert'),
            'key_file': pki.path(pki.server_id, 'key'),
            'allow_unauthenticated_clients': True,
        })

        self.assertEqual(pki.client_sslconfig, {
            'ca_file': pki.path(pki.server_ca_id, 'ca'),
            'check_hostname': False,
            'cert_file': pki.path(pki.client_id, 'cert'),
            'key_file': pki.path(pki.client_id, 'key'),
        })

        self.assertEqual(pki.anonymous_client_sslconfig, {
            'ca_file': pki.path(pki.server_ca_id, 'ca'),
            'check_hostname': False,
        })

        self.assertTrue(path.isdir(pki.ssldir))
        pki.__del__()
        self.assertFalse(path.exists(pki.ssldir))
        pki.__del__()

        # Test when client_pki=False:
        pki = misc.TempPKI(client_pki=False)
        self.assertGreater(path.getsize(pki.path(pki.server_ca_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_ca_id, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_id, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_id, 'cert')), 0)

        self.assertEqual(pki.anonymous_server_sslconfig, {
            'cert_file': pki.path(pki.server_id, 'cert'),
            'key_file': pki.path(pki.server_id, 'key'),
            'allow_unauthenticated_clients': True,
        })

        self.assertEqual(pki.anonymous_client_sslconfig, {
            'ca_file': pki.path(pki.server_ca_id, 'ca'),
            'check_hostname': False,
        })

        self.assertTrue(path.isdir(pki.ssldir))
        pki.__del__()
        self.assertFalse(path.exists(pki.ssldir))
        pki.__del__()

