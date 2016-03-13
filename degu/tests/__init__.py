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
Unit tests for the `degu` package.
"""

from unittest import TestCase
import os
import multiprocessing

import degu
from degu.client import Client, SSLClient
from degu.misc import TempPKI


class TestConstants(TestCase):
    def test_version(self):
        self.assertIsInstance(degu.__version__, str)
        parts = degu.__version__.split('.')
        self.assertEqual(len(parts), 3)
        for part in parts:
            p = int(part)
            self.assertTrue(p >= 0)
            self.assertEqual(str(p), part)

    def test_ADDRESS_CONSTANTS(self):
        self.assertIsInstance(degu.ADDRESS_CONSTANTS, tuple)
        self.assertEqual(degu.ADDRESS_CONSTANTS, (
            degu.IPv6_LOOPBACK,
            degu.IPv6_ANY,
            degu.IPv4_LOOPBACK,
            degu.IPv4_ANY,
        ))
        for address in degu.ADDRESS_CONSTANTS:
            self.assertIsInstance(address, tuple)
            self.assertIn(len(address), {2, 4})
            self.assertIsInstance(address[0], str)
            self.assertIn(address[0], {'::1', '::', '127.0.0.1', '0.0.0.0'})
            if address[0] in {'::1', '::'}:
                self.assertEqual(len(address), 4)
            else:
                self.assertEqual(len(address), 2)
            for value in address[1:]:
                self.assertIsInstance(value, int)
                self.assertEqual(value, 0)


class MyApp:
    def __init__(self, marker):
        self._marker = marker

    def __call__(self, session, request, bodies):
        return (200, 'OK', {}, self._marker)


def my_build_func(marker):
    return MyApp(marker)


class TestFunctions(TestCase):
    def test_start_server(self):
        marker = os.urandom(16)
        (process, address) = degu._start_server(
            ('127.0.0.1', 0), my_build_func, marker
        )
        self.assertIsInstance(process, multiprocessing.Process)
        self.assertIsInstance(address, tuple)
        self.assertEqual(len(address), 2)
        self.assertEqual(address[0], '127.0.0.1')
        self.assertGreater(address[1], 0)
        client = Client(address)
        conn = client.connect()
        response = conn.request('GET', '/', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 16})
        self.assertEqual(response.body.read(), marker)
        conn.close()
        process.terminate()
        process.join()

    def test_start_sslserver(self):
        pki = TempPKI()
        marker = os.urandom(16)
        (process, address) = degu._start_sslserver(
            pki.server_sslconfig, ('127.0.0.1', 0), my_build_func, marker
        )
        self.assertIsInstance(process, multiprocessing.Process)
        self.assertIsInstance(address, tuple)
        self.assertEqual(len(address), 2)
        self.assertEqual(address[0], '127.0.0.1')
        self.assertGreater(address[1], 0)
        client = SSLClient(pki.client_sslconfig, address)
        conn = client.connect()
        response = conn.request('GET', '/', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 16})
        self.assertEqual(response.body.read(), marker)
        conn.close()
        process.terminate()
        process.join()


class TestEmbeddedServer(TestCase):
    def test_init(self):
        for address in (degu.IPv4_LOOPBACK, degu.IPv6_LOOPBACK):
            marker = os.urandom(16)
            server = degu.EmbeddedServer(address, my_build_func, marker)
            self.assertIsInstance(server.process, multiprocessing.Process)
            self.assertIsInstance(server.address, tuple)
            self.assertEqual(len(server.address), len(address))
            self.assertEqual(server.address[0], address[0])
            self.assertGreater(server.address[1], 0)
            self.assertEqual(server.build_func, my_build_func)
            self.assertEqual(server.build_args, (marker,))
            self.assertEqual(server.options, {})

            client = Client(server.address)
            conn = client.connect()
            response = conn.request('GET', '/', {}, None)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.reason, 'OK')
            self.assertEqual(response.headers, {'content-length': 16})
            self.assertEqual(response.body.read(), marker)
            conn.close()
            server.terminate()


class TestEmbeddedSSLServer(TestCase):
    def test_start_sslserver(self):
        for address in (degu.IPv4_LOOPBACK, degu.IPv6_LOOPBACK):
            pki = TempPKI()
            marker = os.urandom(16)
            server = degu.EmbeddedSSLServer(
                pki.server_sslconfig, address, my_build_func, marker
            )
            self.assertEqual(server.sslconfig, pki.server_sslconfig)
            self.assertIsInstance(server.process, multiprocessing.Process)
            self.assertIsInstance(server.address, tuple)
            self.assertEqual(len(server.address), len(address))
            self.assertEqual(server.address[0], address[0])
            self.assertGreater(server.address[1], 0)
            self.assertEqual(server.build_func, my_build_func)
            self.assertEqual(server.build_args, (marker,))
            self.assertEqual(server.options, {})

            client = SSLClient(pki.client_sslconfig, server.address)
            conn = client.connect()
            response = conn.request('GET', '/', {}, None)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.reason, 'OK')
            self.assertEqual(response.headers, {'content-length': 16})
            self.assertEqual(response.body.read(), marker)
            conn.close()
            server.terminate()

