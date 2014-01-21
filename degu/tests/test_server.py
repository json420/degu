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
Unit tests for the `degu.server` module`
"""

from unittest import TestCase
import os
from random import SystemRandom
import socket
import ssl

from dbase32 import random_id

from .helpers import TempDir, DummySocket, DummyFile
from degu.misc import TempPKI
from degu import base, server


class TestFunctions(TestCase):
    def test_build_server_sslctx(self):
        # client_pki=False:
        pki = TempPKI()
        sslctx = server.build_server_sslctx(pki.server_config)
        self.assertIsNone(base.validate_sslctx(sslctx))
        self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
        self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_NONE)

        # client_pki=True:
        pki = TempPKI(client_pki=True)
        sslctx = server.build_server_sslctx(pki.server_config)
        self.assertIsNone(base.validate_sslctx(sslctx))
        self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
        self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)

    def test_parse_request(self):
        # Bad separators:
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET/foo/bar?stuff=junkHTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request Line')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET  /foo/bar?stuff=junk  HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request Line')

        # Bad method:
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('COPY /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Method Not Allowed')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('get /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Method Not Allowed')

        # All manner of URI problems:
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET foo/bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Start')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /../bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI DotDot')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET //bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Double Slash')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo\\/bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Backslash')

        # Same as above, but toss a query into the mix
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Start')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=.. HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI DotDot')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=// HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Double Slash')
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff\\=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Backslash')

        # Multiple "?" present in URI:
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk?other=them HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Query')

        # Bad protocol:
        with self.assertRaises(base.ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk HTTP/1.0')
        self.assertEqual(cm.exception.reason, '505 HTTP Version Not Supported')

        # Test all valid methods:
        for M in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD'):
            line = '{} /foo/bar?stuff=junk HTTP/1.1'.format(M)
            (method, path_list, query) = server.parse_request(line)
            self.assertEqual(method, M)
            self.assertEqual(path_list, ['foo', 'bar'])
            self.assertEqual(query, 'stuff=junk')

        # Test URI permutations:
        cases = [
            ('/', []),
            ('/foo', ['foo']),
            ('/foo/', ['foo', '']),
            ('/foo/bar', ['foo', 'bar']),
            ('/foo/bar/', ['foo', 'bar', '']),
        ]
        for (U, P) in cases:
            for Q in ('', 'stuff=junk'):
                uri = ('?'.join([U, Q]) if Q else U)
                line = 'GET {} HTTP/1.1'.format(uri)
                (method, path_list, query) = server.parse_request(line)
                self.assertEqual(method, 'GET')
                self.assertEqual(path_list, P)
                self.assertEqual(query, Q)
                self.assertEqual(server.reconstruct_uri(path_list, Q), uri)

        # Test URI with a trailing "?" but no query (note that reconstruct_uri()
        # wont round-trip URI such as this):
        self.assertEqual(
            server.parse_request('GET /foo/bar? HTTP/1.1'),
            ('GET', ['foo', 'bar'], '')
        )
        self.assertEqual(
            server.parse_request('GET /foo/bar/? HTTP/1.1'),
            ('GET', ['foo', 'bar', ''], '')
        )
        self.assertEqual(
            server.parse_request('GET /? HTTP/1.1'),
            ('GET', [], '')
        )

    def test_reconstruct_uri(self):
        self.assertEqual(server.reconstruct_uri([], ''), '/')
        self.assertEqual(server.reconstruct_uri([], 'q'), '/?q')
        self.assertEqual(server.reconstruct_uri(['foo'], ''), '/foo')
        self.assertEqual(server.reconstruct_uri(['foo'], 'q'), '/foo?q')
        self.assertEqual(server.reconstruct_uri(['foo', ''], ''), '/foo/')
        self.assertEqual(server.reconstruct_uri(['foo', ''], 'q'), '/foo/?q')
        self.assertEqual(server.reconstruct_uri(['foo', 'bar'], ''), '/foo/bar')
        self.assertEqual(server.reconstruct_uri(['foo', 'bar'], 'q'), '/foo/bar?q')
        self.assertEqual(server.reconstruct_uri(['foo', 'bar', ''], ''), '/foo/bar/')
        self.assertEqual(server.reconstruct_uri(['foo', 'bar', ''], 'q'), '/foo/bar/?q')

    def test_shift_path(self):
        script = []
        path = ['foo', 'bar', 'baz']
        environ = {'script': script, 'path': path}

        self.assertEqual(server.shift_path(environ), 'foo')
        self.assertEqual(environ, {'script': ['foo'], 'path': ['bar', 'baz']})
        self.assertIs(environ['script'], script)
        self.assertIs(environ['path'], path)

        self.assertEqual(server.shift_path(environ), 'bar')
        self.assertEqual(environ, {'script': ['foo', 'bar'], 'path': ['baz']})
        self.assertIs(environ['script'], script)
        self.assertIs(environ['path'], path)

        self.assertEqual(server.shift_path(environ), 'baz')
        self.assertEqual(environ, {'script': ['foo', 'bar', 'baz'], 'path': []})
        self.assertIs(environ['script'], script)
        self.assertIs(environ['path'], path)

        with self.assertRaises(IndexError) as cm:
            server.shift_path(environ)
        self.assertEqual(environ, {'script': ['foo', 'bar', 'baz'], 'path': []})
        self.assertIs(environ['script'], script)
        self.assertIs(environ['path'], path)

    def test_iter_response_lines(self):
        self.assertEqual(
            list(server.iter_response_lines(200, 'OK', {})),
            ['HTTP/1.1 200 OK\r\n', '\r\n']
        )
        self.assertEqual(
            list(server.iter_response_lines(420, 'Enhance Your Calm', None)),
            ['HTTP/1.1 420 Enhance Your Calm\r\n', '\r\n']
        )
        headers = {
            'server': 'Dmedia/14.04',
            'content-type': 'application/json',
            'content-length': 17,
            'date': 'if you buy',
        }
        self.assertEqual(
            list(server.iter_response_lines(404, 'Not Found', headers)),
            [
                'HTTP/1.1 404 Not Found\r\n',
                # Note the headers are in sorted order
                'content-length: 17\r\n',
                'content-type: application/json\r\n',\
                'date: if you buy\r\n',
                'server: Dmedia/14.04\r\n',
                '\r\n',
            ]
        )


class TestHandler(TestCase):
    def test_init(self):
        app = random_id()
        environ = random_id()
        sock = DummySocket()
        handler = server.Handler(app, environ, sock)
        self.assertIs(handler.closed, False)
        self.assertIs(handler.app, app)
        self.assertIs(handler.environ, environ)
        self.assertIs(handler.sock, sock)
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])
        self.assertIs(handler.rfile, sock._rfile)
        self.assertIs(handler.wfile, sock._wfile)

    def test_close(self):
        # We need to override Handler.__init__() for this test:
        class HandlerSubclass(server.Handler):
            def __init__(self, sock, rfile, wfile):
                self.sock = sock
                self.rfile = rfile
                self.wfile = wfile

        sock = DummySocket()
        rfile = DummyFile()
        wfile = DummyFile()
        handler = HandlerSubclass(sock, rfile, wfile)
        self.assertIsNone(handler.close())
        self.assertEqual(sock._calls, ['close'])
        self.assertEqual(rfile._calls, ['close'])
        self.assertEqual(wfile._calls, ['close'])
        self.assertIs(handler.closed, True)

    def test_build_request(self):
        # We need to override Handler.__init__() for this test:
        class HandlerSubclass(server.Handler):
            def __init__(self, rfile):
                self.rfile = rfile

        tmp = TempDir()

        # Test with no request body
        lines = ''.join([
            'GET /foo/bar?stuff=junk HTTP/1.1\r\n',
            'User-Agent: Microfiber/14.04\r\n',
            'Accept: application/json\r\n',
            '\r\n',
        ])
        rfile = tmp.prepare(lines.encode('latin_1'))
        handler = HandlerSubclass(rfile)
        self.assertEqual(handler.build_request(), {
            'method': 'GET',
            'script': [],
            'path': ['foo', 'bar'],
            'query': 'stuff=junk',
            'headers': {
                'user-agent': 'Microfiber/14.04',
                'accept': 'application/json',
            },
            'body': None,
        })

        # Test with a Content-Length header
        data = os.urandom(17)
        lines = ''.join([
            'PUT /foo/bar/baz?hello HTTP/1.1\r\n',
            'User-Agent: Microfiber/14.04\r\n',
            'Content-Length: 17\r\n',
            '\r\n',
        ])
        rfile = tmp.prepare(lines.encode('latin_1') + data)
        handler = HandlerSubclass(rfile)
        req = handler.build_request()
        body = req.pop('body')
        self.assertEqual(req, {
            'method': 'PUT',
            'script': [],
            'path': ['foo', 'bar', 'baz'],
            'query': 'hello',
            'headers': {
                'user-agent': 'Microfiber/14.04',
                'content-length': 17,
            },
        })
        self.assertIsInstance(body, base.Input)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.remaining, 17)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.read(), data)
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.read(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)

        # Test with a Transfer-Encoding header
        chunk1 = os.urandom(21)
        chunk2 = os.urandom(18)
        lines = ''.join([
            'POST / HTTP/1.1\r\n',
            'Transfer-Encoding: chunked\r\n',
            'Content-Type: application/json\r\n',
            '\r\n',
        ])
        filename = tmp.join(random_id())
        fp = open(filename, 'xb')
        fp.write(lines.encode('latin_1'))
        base.write_chunk(fp, chunk1)
        base.write_chunk(fp, chunk2)
        base.write_chunk(fp, b'')
        fp.close()
        fp = open(filename, 'rb')
        handler = HandlerSubclass(fp)
        req = handler.build_request()
        body = req.pop('body')
        self.assertEqual(req, {
            'method': 'POST',
            'script': [],
            'path': [],
            'query': '',
            'headers': {
                'transfer-encoding': 'chunked',
                'content-type': 'application/json',
            },
        })
        self.assertIsInstance(body, base.ChunkedInput)
        self.assertIs(body.rfile, fp)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.readchunk(), chunk1)
        self.assertEqual(body.readchunk(), chunk2)
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)


def demo_app(request):
    return (200, 'OK', {}, None) 


class TestServer(TestCase):
    def test_init(self):
        class Bad:
            pass

        # App not callable
        bad = Bad()
        with self.assertRaises(TypeError) as cm:
            server.Server(bad, '::1')
        self.assertEqual(
            str(cm.exception),
            'app not callable: {!r}'.format(bad)
        )

        # Bad bind_address:
        with self.assertRaises(ValueError) as cm:
            server.Server(demo_app, '192.168.1.1')
        self.assertEqual(str(cm.exception), "invalid bind_address: '192.168.1.1'")

        # IPv6 localhost only:
        inst = server.Server(demo_app, '::1')
        self.assertEqual(inst.scheme, 'http')
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '::1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'http://[::1]:{:d}/'.format(inst.port))

        # IPv6 any:
        inst = server.Server(demo_app, '::')
        self.assertEqual(inst.scheme, 'http')
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '::')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'http://[::1]:{:d}/'.format(inst.port))

        # IPv4 localhost only:
        inst = server.Server(demo_app, '127.0.0.1')
        self.assertEqual(inst.scheme, 'http')
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '127.0.0.1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'http://127.0.0.1:{:d}/'.format(inst.port))

        # IPv4 any:
        inst = server.Server(demo_app, '127.0.0.1')
        self.assertEqual(inst.scheme, 'http')
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '127.0.0.1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'http://127.0.0.1:{:d}/'.format(inst.port))


class TestSSLServer(TestCase):
    def test_init(self):
        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer('foo', demo_app, '::1')
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, demo_app, '::1')
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.PROTOCOL_TLSv1'
        )

        # not (options & ssl.OP_NO_SSLv2)
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, demo_app, '::1')
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_SSLv2'
        )

        # not (options & ssl.OP_NO_COMPRESSION)
        sslctx.options |= ssl.OP_NO_SSLv2
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, demo_app, '::1')
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # Good sslctx from here on:
        sslctx.options |= ssl.OP_NO_COMPRESSION

        class Bad:
            pass

        # App not callable
        bad = Bad()
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, bad, '::1')
        self.assertEqual(
            str(cm.exception),
            'app not callable: {!r}'.format(bad)
        )

        # Bad bind_address:
        with self.assertRaises(ValueError) as cm:
            server.SSLServer(sslctx, demo_app, '192.168.1.1')
        self.assertEqual(str(cm.exception), "invalid bind_address: '192.168.1.1'")

        # IPv6 localhost only:
        inst = server.SSLServer(sslctx, demo_app, '::1')
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '::1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'https://[::1]:{:d}/'.format(inst.port))

        # IPv6 any:
        inst = server.SSLServer(sslctx, demo_app, '::')
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '::')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'https://[::1]:{:d}/'.format(inst.port))

        # IPv4 localhost only:
        inst = server.SSLServer(sslctx, demo_app, '127.0.0.1')
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '127.0.0.1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'https://127.0.0.1:{:d}/'.format(inst.port))

        # IPv4 any:
        inst = server.SSLServer(sslctx, demo_app, '127.0.0.1')
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.app, demo_app)
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.bind_address, '127.0.0.1')
        self.assertIsInstance(inst.port, int)
        self.assertEqual(inst.port, inst.sock.getsockname()[1])
        self.assertEqual(inst.url, 'https://127.0.0.1:{:d}/'.format(inst.port))
