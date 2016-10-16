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
Unit tests for the `degu.server` module`
"""

from unittest import TestCase
import os
from os import path
import io
import stat
import time
from random import SystemRandom
import socket
import ssl
import json
from hashlib import sha1
import struct

from .helpers import TempDir
import degu
from degu.sslhelpers import random_id
from degu.misc import TempPKI, TempServer, TempSSLServer
from degu.client import Client, SSLClient, build_client_sslctx
from degu.base import _TYPE_ERROR
from degu.misc import write_chunk
from degu import rgi, base, server


random = SystemRandom()


def standard_harness_app(session, request, api):
    if len(request.path) == 3 and request.path[0] == 'status':
        code = int(request.path[1])
        reason = request.path[2]
        return (code, reason, {}, None)


class TestFunctions(TestCase):
    def test_build_server_sslctx(self):
        # Bad sslconfig type:
        with self.assertRaises(TypeError) as cm:
            server.build_server_sslctx('bad')
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('sslconfig', dict, str, 'bad')
        )

        # The remaining test both build_server_sslctx() directly, and the
        # pass-through from _validate_server_sslctx():
        server_sslctx_funcs = (
            server.build_server_sslctx,
            server._validate_server_sslctx,
        )

        # Non absulute, non normalized paths:
        good = {
            'cert_file': '/my/server.cert',
            'key_file': '/my/server.key',
            'ca_file': '/my/client.ca',
            'ca_path': '/my/client.ca.dir',
        }
        for key in good.keys():
            for func in server_sslctx_funcs:
                # Relative path:
                bad = good.copy()
                value = 'relative/path'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )

                # Non-normalized path with directory traversal:
                bad = good.copy()
                value = '/my/../secret/path'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )

                # Non-normalized path with trailing slash:
                bad = good.copy()
                value = '/sorry/very/strict/'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )


        pki = TempPKI(client_pki=True)

        # Typical sslconfig with client authentication:
        self.assertEqual(set(pki.server_sslconfig),
            {'cert_file', 'key_file', 'ca_file'}
        )
        for func in server_sslctx_funcs:
            sslctx = func(pki.server_sslconfig)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(sslctx.options & ssl.OP_NO_COMPRESSION)
            self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
            self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)

        # New in Degu 0.3: should not be able to accept connections from
        # unauthenticated clients by merely omitting ca_file/ca_path:
        sslconfig = pki.server_sslconfig
        del sslconfig['ca_file']
        for func in server_sslctx_funcs:
            with self.assertRaises(ValueError) as cm:
                func(sslconfig)
            self.assertEqual(str(cm.exception),
                'must include ca_file or ca_path (or allow_unauthenticated_clients)'
            )

        # Typical config allowing anonymous clients:
        sslconfig['allow_unauthenticated_clients'] = True
        for func in server_sslctx_funcs:
            sslctx = func(sslconfig)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_NONE)
            self.assertTrue(sslctx.options & ssl.OP_NO_COMPRESSION)
            self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
            self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)

        # Cannot mix ca_file/ca_path with allow_unauthenticated_clients:
        sslconfig['ca_file'] = '/my/client.ca'
        for func in server_sslctx_funcs:
            with self.assertRaises(ValueError) as cm:
                func(sslconfig)
            self.assertEqual(str(cm.exception),
                'ca_file/ca_path with allow_unauthenticated_clients'
            )
        sslconfig['ca_path'] = sslconfig.pop('ca_file')
        for func in server_sslctx_funcs:
            with self.assertRaises(ValueError) as cm:
                func(sslconfig)
            self.assertEqual(str(cm.exception),
                'ca_file/ca_path with allow_unauthenticated_clients'
            )

        # True is only allowed value for allow_unauthenticated_clients:
        sslconfig.pop('ca_path')
        for bad in (1, 0, False, None):
            sslconfig['allow_unauthenticated_clients'] = bad
            for func in server_sslctx_funcs:
                with self.assertRaises(ValueError) as cm:
                    func(sslconfig)
                self.assertEqual(str(cm.exception),
                    'True is only allowed value for allow_unauthenticated_clients'
                )

    def test__validate_server_sslctx(self):
        # Bad type:
        with self.assertRaises(TypeError) as cm:
            server._validate_server_sslctx(ssl.SSLContext)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Wrong protocol:
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(ssl.SSLContext(ssl.PROTOCOL_TLSv1))
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.PROTOCOL_TLSv1_2'
        )

        # Don't allow ssl.CERT_OPTIONAL:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.verify_mode = ssl.CERT_OPTIONAL
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.verify_mode cannot be ssl.CERT_OPTIONAL'
        )

        # options missing OP_NO_COMPRESSION:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.assertIs(sslctx.verify_mode, ssl.CERT_NONE)
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # options missing OP_SINGLE_ECDH_USE:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_SINGLE_ECDH_USE'
        )

        # options missing OP_CIPHER_SERVER_PREFERENCE:
        sslctx.options |= ssl.OP_SINGLE_ECDH_USE
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE'
        )

        # All good:
        sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        self.assertIs(server._validate_server_sslctx(sslctx), sslctx)

        # Now again, this time with CERT_REQUIRED:
        # options missing OP_NO_COMPRESSION:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.verify_mode = ssl.CERT_REQUIRED
        self.assertIs(sslctx.verify_mode, ssl.CERT_REQUIRED)
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # options missing OP_SINGLE_ECDH_USE:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_SINGLE_ECDH_USE'
        )

        # options missing OP_CIPHER_SERVER_PREFERENCE:
        sslctx.options |= ssl.OP_SINGLE_ECDH_USE
        with self.assertRaises(ValueError) as cm:
            server._validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE'
        )

        # All good:
        sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        self.assertIs(server._validate_server_sslctx(sslctx), sslctx)

    def test_get_credentials(self):
        class MockSocket:
            def __init__(self, cred):
                self._cred = cred
                self._calls = []

            def setsockopt(self, *args):
                self._calls.append(('setsockopt',) + args)

            def getsockopt(self, *args):
                self._calls.append(('getsockopt',) + args)
                return struct.pack('3i', *self._cred)

        cred = (9999, 8888, 7777)
        sock = MockSocket(cred)
        self.assertEqual(server._get_credentials(sock), cred)
        size = struct.calcsize('3i')
        self.assertEqual(sock._calls, [
            ('setsockopt', socket.SOL_SOCKET, socket.SO_PASSCRED, 1),
            ('getsockopt', socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        ])


class BadApp:
    """
    Not callable.
    """


def good_app(session, request, api):
    return (200, 'OK', {}, None)


class BadConnectionHandler:
    def __call__(self, session, request, api):
        pass

    on_connect = 'nope'


class GoodConnectionHandler:
    def __call__(self, session, request, api):
        pass

    def on_connect(self, session, sock):
        pass


class TestServer(TestCase):
    def test_init(self):
        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            server.Server(1234, good_app)
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        bad_addresses = [
            ('::1',),
            ('127.0.0.1',),
            ('::1', 0, 0),
            ('127.0.0.1', 0, 0),
            ('::1', 0, 0, 0, 0),
            ('127.0.0.1', 0, 0, 0, 0),
        ]
        for address in bad_addresses:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                server.Server(address, good_app)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # Non-normalized socket filename:
        with self.assertRaises(ValueError) as cm:
            server.Server('foo', good_app)
        self.assertEqual(str(cm.exception),
            "address: bad socket filename: 'foo'"
        )

        # app not callable:
        bad_app = BadApp()
        with self.assertRaises(TypeError) as cm:
            server.Server(degu.IPv6_LOOPBACK, bad_app)
        self.assertEqual(str(cm.exception),
            'app: not callable: {!r}'.format(bad_app)
        )

        # app.on_connect not callable:
        bad_app = BadConnectionHandler()
        with self.assertRaises(TypeError) as cm:
            server.Server(degu.IPv6_LOOPBACK, bad_app)
        self.assertEqual(str(cm.exception),
            'app.on_connect: not callable: {!r}'.format(bad_app)
        )

        # Good app.on_connect:
        app = GoodConnectionHandler()
        inst = server.Server(degu.IPv6_LOOPBACK, app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, app)

        # IPv6 loopback:
        inst = server.Server(degu.IPv6_LOOPBACK, good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv6 any:
        inst = server.Server(degu.IPv6_ANY, good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv4 loopback:
        inst = server.Server(degu.IPv4_LOOPBACK, good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('127.0.0.1', port))
        self.assertIs(inst.app, good_app)

        # IPv4 any:
        inst = server.Server(degu.IPv4_ANY, good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('0.0.0.0', port))
        self.assertIs(inst.app, good_app)

        # Socket filename:
        tmp = TempDir()
        filename = tmp.join('my.socket')
        self.assertFalse(path.exists(filename))
        inst = server.Server(filename, good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.address, filename)
        self.assertEqual(inst.sock.getsockname(), filename)
        self.assertIs(inst.app, good_app)
        self.assertTrue(stat.S_ISSOCK(os.stat(filename).st_mode))

        # Linux abstract socket names:
        inst = server.Server(b'', good_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.address, inst.sock.getsockname())
        self.assertIsInstance(inst.address, bytes)
        self.assertIs(inst.app, good_app)

        # Test options:
        inst = server.Server(degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(inst.timeout, 30)
        self.assertEqual(inst.max_connections, 50)
        self.assertEqual(inst.max_requests, 1000)
        self.assertEqual(inst.options, {})
        options = {
            'timeout': 1,
            'max_connections': 2,
            'max_requests': 3,  
        }
        for (key, val) in options.items():
            kw = {key: val}
            inst = server.Server(degu.IPv6_LOOPBACK, good_app, **kw)
            self.assertEqual(getattr(inst, key), val)
            self.assertEqual(inst.options, kw)

        # Test unsupported options:
        with self.assertRaises(TypeError) as cm:
            server.Server(degu.IPv6_LOOPBACK, good_app, foo=17)
        self.assertEqual(str(cm.exception),
            'unsupported Server() **options: foo'
        )
        with self.assertRaises(TypeError) as cm:
            server.Server(degu.IPv6_LOOPBACK, good_app, foo=17, bar=19)
        self.assertEqual(str(cm.exception),
            'unsupported Server() **options: bar, foo'
        )

    def test_repr(self):
        pairs = (
            (good_app, 'degu.tests.test_server.good_app'),
            (rgi.Validator, 'degu.rgi.Validator'),
            (rgi.Validator(good_app), 'degu.rgi.Validator(<...>)'),
        )

        class Custom(server.Server):
            pass    

        for (app, fqname) in pairs:
            inst = server.Server(degu.IPv6_LOOPBACK, app)
            self.assertEqual(repr(inst),
                'Server({!r}, {})'.format(inst.address, fqname)
            )
            inst = Custom(degu.IPv6_LOOPBACK, app)
            self.assertEqual(repr(inst),
                'Custom({!r}, {})'.format(inst.address, fqname)
            )


class TestSSLServer(TestCase):
    def test_init(self):
        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer('foo', degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.PROTOCOL_TLSv1_2'
        )

        # Note: Python 3.3.4 (and presumably 3.4.0) now disables SSLv2 by
        # default (which is good); Degu enforces this (also good), but because
        # we cannot unset the ssl.OP_NO_SSLv2 bit, we can't unit test to check
        # that Degu enforces this, so for now, we set the bit here so it works
        # with Python 3.3.3 still; see: http://bugs.python.org/issue20207
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.options |= ssl.OP_NO_SSLv2

        # not (options & ssl.OP_NO_COMPRESSION)
        sslctx.options |= ssl.OP_NO_SSLv2
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, '::1', good_app)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # not (options & ssl.OP_SINGLE_ECDH_USE)
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, '::1', good_app)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_SINGLE_ECDH_USE'
        )

        # not (options & ssl.OP_CIPHER_SERVER_PREFERENCE)
        sslctx.options |= ssl.OP_SINGLE_ECDH_USE
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, '::1', good_app)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE'
        )

        # Good sslctx from here on:
        sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, 1234, good_app)
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        bad_addresses = [
            ('::1',),
            ('127.0.0.1',),
            ('::1', 0, 0),
            ('127.0.0.1', 0, 0),
            ('::1', 0, 0, 0, 0),
            ('127.0.0.1', 0, 0, 0, 0),
        ]
        for address in bad_addresses:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                server.SSLServer(sslctx, address, good_app)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # app not callable:
        bad_app = BadApp()
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, degu.IPv6_LOOPBACK, bad_app)
        self.assertEqual(str(cm.exception),
            'app: not callable: {!r}'.format(bad_app)
        )

        # app.on_connect not callable:
        bad_app = BadConnectionHandler()
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, degu.IPv6_LOOPBACK, bad_app)
        self.assertEqual(str(cm.exception),
            'app.on_connect: not callable: {!r}'.format(bad_app)
        )

        # Good app.on_connect:
        app = GoodConnectionHandler()
        inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, app)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, app)

        # IPv6 loopback:
        inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv6 any:
        inst = server.SSLServer(sslctx, degu.IPv6_ANY, good_app)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv4 loopback:
        inst = server.SSLServer(sslctx, degu.IPv4_LOOPBACK, good_app)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('127.0.0.1', port))
        self.assertIs(inst.app, good_app)

        # IPv4 any:
        inst = server.SSLServer(sslctx, degu.IPv4_ANY, good_app)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('0.0.0.0', port))
        self.assertIs(inst.app, good_app)

        # Test options:
        inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(inst.timeout, 30)
        self.assertEqual(inst.max_connections, 50)
        self.assertEqual(inst.max_requests, 1000)
        self.assertEqual(inst.options, {})
        options = {
            'timeout': 1,
            'max_connections': 2,
            'max_requests': 3,  
        }
        for (key, val) in options.items():
            kw = {key: val}
            inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app, **kw)
            self.assertEqual(getattr(inst, key), val)
            self.assertEqual(inst.options, kw)

        # Test unsupported options:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app, foo=17)
        self.assertEqual(str(cm.exception),
            'unsupported SSLServer() **options: foo'
        )
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app, foo=17, bar=19)
        self.assertEqual(str(cm.exception),
            'unsupported SSLServer() **options: bar, foo'
        )

    def test_repr(self):
        pairs = (
            (good_app, 'degu.tests.test_server.good_app'),
            (rgi.Validator, 'degu.rgi.Validator'),
            (rgi.Validator(good_app), 'degu.rgi.Validator(<...>)'),
        )
        pki = TempPKI()
        sslctx = server.build_server_sslctx(pki.server_sslconfig)

        class Custom(server.SSLServer):
            pass    

        for (app, fqname) in pairs:
            inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, app)
            self.assertEqual(repr(inst),
                'SSLServer(<sslctx>, {!r}, {})'.format(inst.address, fqname)
            )
            inst = Custom(sslctx, degu.IPv6_LOOPBACK, app)
            self.assertEqual(repr(inst),
                'Custom(<sslctx>, {!r}, {})'.format(inst.address, fqname)
            )


CHUNKS = []
for i in range(2):
    size = random.randint(1, 500)
    CHUNKS.append(os.urandom(size))
CHUNKS.append(b'')
CHUNKS = tuple(CHUNKS)
wfile = io.BytesIO()
for data in CHUNKS:
    write_chunk(wfile, (None, data))
ENCODED_CHUNKS = wfile.getvalue()
del wfile


def chunked_request_app(session, request, api):
    assert request.method == 'POST'
    assert request.mount == []
    assert request.path == []
    assert isinstance(request.body, api.ChunkedBody)
    assert request.headers['transfer-encoding'] == 'chunked'
    result = []
    for (extension, data) in request.body:
        result.append(sha1(data).hexdigest())
    body = json.dumps(result).encode('utf-8')
    headers = {'content-length': len(body), 'content-type': 'application/json'}
    return (200, 'OK', headers, body)


def chunked_response_app(session, request, api):
    assert request.method == 'GET'
    assert request.mount == []
    assert request.body is None
    headers = {'transfer-encoding': 'chunked'}
    if request.path == ['foo']:
        rfile = io.BytesIO(ENCODED_CHUNKS)
    elif request.path == ['bar']:
        rfile = io.BytesIO(b'0\r\n\r\n')
    else:
        return (404, 'Not Found', {}, None)
    body = api.ChunkedBody(rfile)
    return (200, 'OK', headers, body)


DATA1 = os.urandom(1776)
DATA2 = os.urandom(3469)
DATA = DATA1 + DATA2


def response_app(session, request, api):
    assert request.method == 'GET'
    assert request.mount == []
    assert request.body is None
    if request.path == ['foo']:
        body = api.Body(io.BytesIO(DATA), len(DATA))
    elif request.path == ['bar']:
        body = api.Body(io.BytesIO(), 0)
    else:
        return (404, 'Not Found', {}, None)
    headers = {'content-length': body.content_length}
    return (200, 'OK', headers, body)


def timeout_app(session, request, api):
    assert request.method == 'POST'
    assert request.mount == []
    assert request.body is None
    if request.path == ['foo']:
        # Used to test timeout on server side:
        return (200, 'OK', {}, None)
    if request.path == ['bar']:
        # Used to test timeout on client side:
        #time.sleep(CLIENT_SOCKET_TIMEOUT + 2)
        return (400, 'Bad Request', {}, None)
    return (404, 'Not Found', {}, None)


class AppWithConnectionHandler:
    def __init__(self,  marker, accept):
        assert isinstance(marker, bytes) and len(marker) > 0
        assert isinstance(accept, bool)
        self.marker = marker
        self.accept = accept

    def __call__(self, session, request, api):
        return (200, 'OK', {}, self.marker)

    def on_connect(self, session, sock):
        return self.accept



class TestLiveServer(TestCase):
    address = degu.IPv4_LOOPBACK

    def setUp(self):
        if os.environ.get('DEGU_TEST_SKIP_SLOW') == 'true':
            self.skipTest('skipping as DEGU_TEST_SKIP_SLOW is set')

    def build_with_app(self, app, **options):
        httpd = TempServer(self.address, rgi.Validator(app), **options)
        client = Client(httpd.address)
        return (httpd, client)

    def test_timeout(self):
        """
        Do a realistic live socket timeout test.

        This is a very important test that we absolutely want to run during
        package builds on the build servers, despite the fact that it's a
        rather time consuming test.

        However, during day to day development, it's often handy to skip the
        timeout tests for the sake of getting quicker feedback on a code change.

        You can run all the unit tests minus the timeout tests like this::

            $ ./setup.py test --skip-slow

        You can also accomplish the same with an environment variable::

            $ DEGU_TEST_SKIP_SLOW=true ./setup.py test

        """

        timeout = 3
        (httpd, client) = self.build_with_app(timeout_app, timeout=timeout)
        conn = client.connect()

        # Make an inital request:
        self.assertEqual(conn.request('POST', '/foo', {}, None), 
            (200, 'OK', {}, None)
        )

        # Wait till 1.5 seconds *before* the timeout should happen, to make sure
        # connection is still open:
        time.sleep(timeout - 1)
        self.assertEqual(conn.request('POST', '/foo', {}, None),
            (200, 'OK', {}, None)
        )

        # Now wait till 1.5 seconds *after* the timeout should have happened, to
        # make sure the connection was closed by the server:
        time.sleep(timeout + 1.5)
        with self.assertRaises(ConnectionError):
            conn.request('POST', '/foo', {}, None)
        self.assertIs(conn.closed, True)
        conn = client.connect()
        self.assertEqual(conn.request('POST', '/foo', {}, None),
            (200, 'OK', {}, None)
        )
        httpd.terminate()

    def test_chunked_request(self):
        (httpd, client) = self.build_with_app(chunked_request_app)
        conn = client.connect()

        body = base.api.ChunkedBody(io.BytesIO(ENCODED_CHUNKS))
        response = conn.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 132, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.api.Body)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(chunk).hexdigest() for chunk in CHUNKS]
        )

        body = base.api.ChunkedBody(io.BytesIO(b'0\r\n\r\n'))
        response = conn.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 44, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.api.Body)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(b'').hexdigest()]
        )

        httpd.terminate()

    def test_chunked_response(self):
        (httpd, client) = self.build_with_app(chunked_response_app)
        conn = client.connect()

        response = conn.request('GET', '/foo', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.api.ChunkedBody)
        self.assertEqual(tuple(response.body),
            tuple((None, data) for data in CHUNKS)
        )

        response = conn.request('GET', '/bar', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.api.ChunkedBody)
        self.assertEqual(list(response.body), [(None, b'')])

        response = conn.request('GET', '/baz', {}, None)
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = conn.request('GET', '/foo', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.api.ChunkedBody)
        self.assertEqual(tuple(response.body),
            tuple((None, data) for data in CHUNKS)
        )
        httpd.terminate()

    def test_response(self):
        (httpd, client) = self.build_with_app(response_app)
        conn = client.connect()

        response = conn.request('GET', '/foo', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.api.Body)
        self.assertEqual(response.body.read(), DATA)

        response = conn.request('GET', '/bar', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 0})
        self.assertIsInstance(response.body, base.api.Body)
        self.assertEqual(response.body.read(), b'')

        response = conn.request('GET', '/baz', {}, None)
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = conn.request('GET', '/foo', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.api.Body)
        self.assertEqual(response.body.read(), DATA)
        httpd.terminate()

    def test_always_accept_connections(self):
        marker = os.urandom(16)
        app = AppWithConnectionHandler(marker, True)
        (httpd, client) = self.build_with_app(app)
        for i in range(11):
            conn = client.connect()
            for j in range(17):
                response = conn.request('GET', '/', {}, None)
                self.assertEqual(response.status, 200)
                self.assertEqual(response.reason, 'OK')
                self.assertEqual(response.headers, {'content-length': 16})
                self.assertIsInstance(response.body, base.api.Body)
                self.assertEqual(response.body.read(), marker)
            conn.close()
        httpd.terminate()

    def test_always_reject_connections(self):
        marker = os.urandom(16)
        app = AppWithConnectionHandler(marker, False)
        (httpd, client) = self.build_with_app(app)
        for i in range(11):
            conn = client.connect()
            with self.assertRaises(ConnectionError):
                conn.request('GET', '/', {}, None)
            self.assertIs(conn.closed, True)
        httpd.terminate()

    def test_ok_status(self):
        (httpd, client) = self.build_with_app(standard_harness_app,
                                              max_requests=600)
        conn = client.connect()
        # At no point should the connection be closed by the server:
        for status in range(100, 400):
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            response = conn.request('GET', uri, {}, None)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
            # Again with a 2nd random reason string:
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            response = conn.request('GET', uri, {}, None)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
        conn.close()
        httpd.terminate()

    def test_error_status(self):
        (httpd, client) = self.build_with_app(standard_harness_app)
        for status in range(400, 600):
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            conn = client.connect()
            response = conn.request('GET', uri, {}, None)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
            if status in {404, 409, 412}:
                # Connection should not be closed for 404, 409, 412:
                response = conn.request('GET', uri, {}, None)
                self.assertEqual(response.status, status)
                self.assertEqual(response.reason, reason)
                self.assertEqual(response.headers, {})
                self.assertIsNone(response.body)
                conn.close()
            else:
                # But connection should be closed for all other status >= 400:
                with self.assertRaises(ConnectionError):
                    conn.request('GET', uri, {}, None)
                self.assertIs(conn.closed, True)
        httpd.terminate()

    def test_max_connections(self):
        uri = '/status/404/Nope'
        for value in (11, 17):
            (httpd, client) = self.build_with_app(standard_harness_app,
                                                  max_connections=value)
            allconns = []
            for i in range(value):
                conn = client.connect()
                allconns.append(conn)
                response = conn.request('GET', uri, {}, None)
                self.assertEqual(response.status, 404)
                self.assertEqual(response.reason, 'Nope')
                self.assertEqual(response.headers, {})
                self.assertIsNone(response.body)
            with self.assertRaises((ConnectionError, ssl.SSLError)):
                conn = client.connect()
                conn.request('GET', uri, {}, None)
            for conn in allconns:
                conn.close()
            httpd.terminate()

    def test_max_requests(self):
        uri = '/status/404/Nope'
        for value in (17, 27, 37):
            (httpd, client) = self.build_with_app(standard_harness_app,
                                                  max_requests=value)
            conn = client.connect()
            for i in range(value):
                response = conn.request('GET', uri, {}, None)
                self.assertEqual(response.status, 404)
                self.assertEqual(response.reason, 'Nope')
                self.assertEqual(response.headers, {})
                self.assertIsNone(response.body)
            with self.assertRaises(ConnectionError):
                conn.request('GET', uri, {}, None)
            self.assertIs(conn.closed, True)
            httpd.terminate()


class TestLiveServer_AF_INET6(TestLiveServer):
    address = degu.IPv6_LOOPBACK


class TestLiveServer_AF_UNIX(TestLiveServer):
    def build_with_app(self, app, **options):
        tmp = TempDir()
        filename = tmp.join('my.socket')
        httpd = TempServer(filename, rgi.Validator(app), **options)
        httpd.tmp = tmp
        return (httpd, Client(httpd.address))


def ssl_app(session, request, api):
#    assert session['ssl_cipher'] == (
#        'ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128
#    )
#    assert session['ssl_compression'] is None
    assert request.method == 'GET'
    assert request.mount == []
    assert request.body is None
    return (200, 'OK', {}, None)


class TestLiveSSLServer(TestLiveServer):
    def build_with_app(self, app, **options):
        pki = TempPKI()
        httpd = TempSSLServer(
            pki.server_sslconfig, self.address, rgi.Validator(app), **options
        )
        httpd.pki = pki
        sslctx = build_client_sslctx(pki.client_sslconfig)
        return (httpd, SSLClient(sslctx, httpd.address))

    def test_ssl(self):
        pki = TempPKI(client_pki=True)
        server_config = pki.server_sslconfig
        client_config = pki.client_sslconfig
        httpd = TempSSLServer(server_config, self.address,  ssl_app)

        # Test from a non-SSL client:
        client = Client(httpd.address)
        conn = client.connect()
        with self.assertRaises(ConnectionResetError) as cm:
            conn.request('GET', '/', {}, None)
        self.assertEqual(str(cm.exception), '[Errno 104] Connection reset by peer')
        self.assertIs(conn.closed, True)

        # Test with no client cert:
        sslctx = build_client_sslctx({'ca_file': client_config['ca_file']})
        client = SSLClient(sslctx, httpd.address)
        with self.assertRaises(ssl.SSLError) as cm:
            client.connect()
        self.assertTrue(
            str(cm.exception).startswith('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]')
        )
        self.assertIs(conn.closed, True)

        # Test with the wrong client cert (not signed by client CA):
        sslctx = build_client_sslctx({
            'ca_file': client_config['ca_file'],
            'cert_file': server_config['cert_file'],
            'key_file': server_config['key_file'],
        })
        client = SSLClient(sslctx, httpd.address)
        with self.assertRaises(ssl.SSLError) as cm:
            client.connect()
        self.assertTrue(
            str(cm.exception).startswith('[SSL: TLSV1_ALERT_UNKNOWN_CA]')
        )
        self.assertIs(conn.closed, True)

        # Test with a properly configured SSLClient:
        sslctx = build_client_sslctx(client_config)
        client = SSLClient(sslctx, httpd.address)
        conn = client.connect()
        response = conn.request('GET', '/', {}, None)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertIsNone(response.body)

        # Test when check_hostname is True:
        conn.close()
        client.sslctx.check_hostname = True
        with self.assertRaises(ssl.CertificateError) as cm:
            client.connect()

        httpd.terminate()


class TestLiveSSLServer_AF_INET6(TestLiveSSLServer):
    address = degu.IPv6_LOOPBACK

