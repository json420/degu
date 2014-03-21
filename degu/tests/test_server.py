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
from os import path
import stat
import time
from random import SystemRandom
import socket
import ssl
import json
from hashlib import sha1

from .helpers import TempDir, DummySocket, DummyFile
import degu
from degu.sslhelpers import random_id
from degu.misc import TempPKI, TempServer, TempSSLServer
from degu.client import Client, CLIENT_SOCKET_TIMEOUT
from degu.base import TYPE_ERROR
from degu import base, server


random = SystemRandom()


class TestFunctions(TestCase):
    def test_build_server_sslctx(self):
        pki = TempPKI(client_pki=True)

        # Typical config with client authentication:
        config = pki.get_server_config()
        self.assertEqual(set(config), {'cert_file', 'key_file', 'ca_file'})
        sslctx = server.build_server_sslctx(config)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(sslctx.options & ssl.OP_NO_COMPRESSION)
        self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
        self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)

        # New in Degu 0.3: should not be able to accept connections from
        # unauthenticated clients by merely omitting ca_file/ca_path:
        del config['ca_file']
        with self.assertRaises(ValueError) as cm:
            server.build_server_sslctx(config)
        self.assertEqual(str(cm.exception),
            'must include ca_file or ca_path (or allow_unauthenticated_clients)'
        )

        # Typical config allowing anonymous clients:
        config['allow_unauthenticated_clients'] = True
        sslctx = server.build_server_sslctx(config)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_NONE)
        self.assertTrue(sslctx.options & ssl.OP_NO_COMPRESSION)
        self.assertTrue(sslctx.options & ssl.OP_SINGLE_ECDH_USE)
        self.assertTrue(sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)

        # Cannot mix ca_file/ca_path with allow_unauthenticated_clients:
        config['ca_file'] = 'whatever'
        with self.assertRaises(ValueError) as cm:
            server.build_server_sslctx(config)
        self.assertEqual(str(cm.exception),
            'cannot include ca_file/ca_path allow_unauthenticated_clients'
        )
        config['ca_path'] = config.pop('ca_file')
        with self.assertRaises(ValueError) as cm:
            server.build_server_sslctx(config)
        self.assertEqual(str(cm.exception),
            'cannot include ca_file/ca_path allow_unauthenticated_clients'
        )

        # True is only allowed value for allow_unauthenticated_clients:
        config.pop('ca_path')
        for bad in (1, 0, False, None):
            config['allow_unauthenticated_clients'] = bad
            with self.assertRaises(ValueError) as cm:
                server.build_server_sslctx(config)
            self.assertEqual(str(cm.exception),
                'True is only allowed value for allow_unauthenticated_clients'
            )

    def test_parse_request(self):
        # Bad separators:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET/foo/bar?stuff=junkHTTP/1.1')
        self.assertEqual(str(cm.exception), 'need more than 1 value to unpack')
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET MY /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 3)'
        )
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar\rstuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 3)'
        )

        # Multiple "?" present in URI:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk?other=them HTTP/1.1')
        self.assertEqual(str(cm.exception),
            "bad request uri: '/foo/bar?stuff=junk?other=them'"
        )

        # All manner of path problems:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET foo HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: 'foo'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET foo/bar HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: 'foo/bar'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET // HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '//'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo// HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo//'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo//bar HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo//bar'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar// HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo/bar//'")

        # Same as above, but toss a query into the mix:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET ?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: ''")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET foo?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: 'foo'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: 'foo/bar'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET //?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '//'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo//?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo//'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo//bar?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo//bar'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar//?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad request path: '/foo/bar//'")

        # Bad protocol:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk HTTP/1.0')
        self.assertEqual(str(cm.exception), "bad HTTP protocol: 'HTTP/1.0'")

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

    def test_validate_response(self):
        # status:
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, ('200', None, None, None))
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('status', int, str, '200')
        )
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (99, None, None, None))
        self.assertEqual(str(cm.exception),
            'status: need 100 <= status <= 599; got 99'
        )
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (600, None, None, None))
        self.assertEqual(str(cm.exception),
            'status: need 100 <= status <= 599; got 600'
        )

        # reason:
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, b'OK', None, None))
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('reason', str, bytes, b'OK')
        )
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (200, '', None, None))
        self.assertEqual(str(cm.exception), 'reason: cannot be empty')
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (200, ' OK', None, None))
        self.assertEqual(str(cm.exception), "reason: surrounding whitespace: ' OK'")
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (200, 'OK ', None, None))
        self.assertEqual(str(cm.exception), "reason: surrounding whitespace: 'OK '")

        # headers:
        headers = [('content-type', 'application/json')]
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, list, headers)
        )
        headers = {17: 'ok'}
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            "bad header name type: <class 'int'>: 17"
        )
        headers = {'Content-Type': 'application/json', 'content-length': 17}
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            "non-casefolded header name: 'Content-Type'"
        )
        headers = {'content-type': 'application/json', 'content-length': '17'}
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("headers['content-length']", int, str, '17')
        )
        headers = {'content-type': 'application/json', 'transfer-encoding': 'globbed'}
        with self.assertRaises(ValueError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            "headers['transfer-encoding']: need 'chunked'; got 'globbed'"
        )
        headers = {'content-type': 'application/json', 'hello': 17}
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, 'OK', headers, None))
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("headers['hello']", str, int, 17)
        )

        # body:
        with self.assertRaises(TypeError) as cm:
            server.validate_response({}, (200, 'OK', {}, 'hello'))
        self.assertEqual(str(cm.exception),
            "body: not valid type: <class 'str'>: 'hello'"
        )
        # isinstance(body, (bytes, bytearray):
        request = {'method': 'GET'}
        for body in [b'hello', bytearray(b'hello')]:
            headers = {}
            self.assertIsNone(
                server.validate_response(request, (200, 'OK', headers, body))
            )
            self.assertEqual(headers, {'content-length': 5})
            headers = {'content-length': 6}
            with self.assertRaises(ValueError) as cm:
                server.validate_response(request, (200, 'OK', headers, body))
            self.assertEqual(str(cm.exception),
                "headers['content-length'] != len(body): 6 != 5"
            )
        # isinstance(body, (Output, FileOutput)):
        tmp = TempDir()
        fp = tmp.prepare(b'hello')
        for body in [base.Output(b'hello', 5), base.FileOutput(fp, 5)]:
            headers = {}
            self.assertIsNone(
                server.validate_response(request, (200, 'OK', headers, body))
            )
            self.assertEqual(headers, {'content-length': 5})
            headers = {'content-length': 6}
            with self.assertRaises(ValueError) as cm:
                server.validate_response(request, (200, 'OK', headers, body))
            self.assertEqual(str(cm.exception),
                "headers['content-length'] != body.content_length: 6 != 5"
            )
        # isinstance(body, ChunkedOutput):
        body = base.ChunkedOutput([b'hello', b'naughty', b'nurse'])
        headers = {}
        self.assertIsNone(
            server.validate_response(request, (200, 'OK', headers, body))
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        # body is None:
        headers = {}
        self.assertIsNone(
            server.validate_response(request, (200, 'OK', headers, None))
        )
        self.assertEqual(headers, {})

        # method=HEAD, body is not None:
        request = {'method': 'HEAD'}
        with self.assertRaises(TypeError) as cm:
            server.validate_response(request, (200, 'OK', {}, b'hello'))
        self.assertEqual(str(cm.exception),
            'response body must be None when request method is HEAD'
        )

        # method=HEAD, body=None:
        headers = {}
        self.assertIsNone(
            server.validate_response(request, (200, 'OK', headers, None))
        )
        self.assertEqual(headers, {})

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


class BadApp:
    """
    Not callable.
    """


def good_app(request):
    return (200, 'OK', {}, None)


class TestServer(TestCase):
    def test_init(self):
        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            server.Server(1234, good_app)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
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

        # IPv6 loopback:
        inst = server.Server(degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv6 any:
        inst = server.Server(degu.IPv6_ANY, good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv4 loopback:
        inst = server.Server(degu.IPv4_LOOPBACK, good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('127.0.0.1', port))
        self.assertIs(inst.app, good_app)

        # IPv4 any:
        inst = server.Server(degu.IPv4_ANY, good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('0.0.0.0', port))
        self.assertIs(inst.app, good_app)

        # Socket filename:
        tmp = TempDir()
        filename = tmp.join('my.socket')
        self.assertFalse(path.exists(filename))
        inst = server.Server(filename, good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.address, filename)
        self.assertEqual(inst.sock.getsockname(), filename)
        self.assertIs(inst.app, good_app)
        self.assertTrue(stat.S_ISSOCK(os.stat(filename).st_mode))

        # Linux abstract socket names:
        inst = server.Server(b'', good_app)
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        self.assertEqual(inst.address, inst.sock.getsockname())
        self.assertIsInstance(inst.address, bytes)
        self.assertIs(inst.app, good_app)

    def test_repr(self):
        inst = server.Server(degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(repr(inst),
            'Server({!r}, {!r})'.format(inst.address, good_app)
        )

        class Custom(server.Server):
            pass

        inst = Custom(degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(repr(inst),
            'Custom({!r}, {!r})'.format(inst.address, good_app)
        )

    def test_build_base_environ(self):
        class ServerSubclass(server.Server):
            def __init__(self, address):
                self.address = address

        address = (random_id(), random_id())
        inst = ServerSubclass(address)
        self.assertEqual(inst.build_base_environ(), {
            'server': address,
            'scheme': 'http',
            'rgi.ResponseBody': base.Output,
            'rgi.FileResponseBody': base.FileOutput,
            'rgi.ChunkedResponseBody': base.ChunkedOutput,
        })


class TestSSLServer(TestCase):
    def test_init(self):
        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer('foo', degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
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

        # Good sslctx from here on:
        sslctx.options |= ssl.OP_NO_COMPRESSION

        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            server.SSLServer(sslctx, 1234, good_app)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
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

        # IPv6 loopback:
        inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv6 any:
        inst = server.SSLServer(sslctx, degu.IPv6_ANY, good_app)
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::', port, 0, 0))
        self.assertIs(inst.app, good_app)

        # IPv4 loopback:
        inst = server.SSLServer(sslctx, degu.IPv4_LOOPBACK, good_app)
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('127.0.0.1', port))
        self.assertIs(inst.app, good_app)

        # IPv4 any:
        inst = server.SSLServer(sslctx, degu.IPv4_ANY, good_app)
        self.assertEqual(inst.scheme, 'https')
        self.assertIs(inst.sslctx, sslctx)
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('0.0.0.0', port))
        self.assertIs(inst.app, good_app)

    def test_repr(self):
        pki = TempPKI()
        sslctx = server.build_server_sslctx(pki.get_server_config())
        inst = server.SSLServer(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(repr(inst),
            'SSLServer({!r}, {!r}, {!r})'.format(sslctx, inst.address, good_app)
        )

        class Custom(server.SSLServer):
            pass

        inst = Custom(sslctx, degu.IPv6_LOOPBACK, good_app)
        self.assertEqual(repr(inst),
            'Custom({!r}, {!r}, {!r})'.format(sslctx, inst.address, good_app)
        )

    def test_build_base_environ(self):
        class SSLServerSubclass(server.SSLServer):
            def __init__(self, address):
                self.address = address

        address = (random_id(), random_id())
        inst = SSLServerSubclass(address)
        self.assertEqual(inst.build_base_environ(), {
            'server': address,
            'scheme': 'https',
            'rgi.ResponseBody': base.Output,
            'rgi.FileResponseBody': base.FileOutput,
            'rgi.ChunkedResponseBody': base.ChunkedOutput,
        })


CHUNKS = []
for i in range(7):
    size = random.randint(1, 5000)
    CHUNKS.append(os.urandom(size))
CHUNKS.append(b'')
CHUNKS = tuple(CHUNKS)


def chunked_request_app(request):
    assert request['method'] == 'POST'
    assert request['script'] == []
    assert request['path'] == []
    assert isinstance(request['body'], base.ChunkedInput)
    assert request['headers']['transfer-encoding'] == 'chunked'
    result = []
    for chunk in request['body']:
        result.append(sha1(chunk).hexdigest())
    body = json.dumps(result).encode('utf-8')
    headers = {'content-length': len(body), 'content-type': 'application/json'}
    return (200, 'OK', headers, body)


def chunked_response_app(request):
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    headers = {'transfer-encoding': 'chunked'}
    if request['path'] == ['foo']:
        body = request['rgi.ChunkedResponseBody'](CHUNKS)
    elif request['path'] == ['bar']:
        body = request['rgi.ChunkedResponseBody']([b''])
    else:
        return (404, 'Not Found', {}, None)
    return (200, 'OK', headers, body)


DATA1 = os.urandom(1776)
DATA2 = os.urandom(3469)
DATA = DATA1 + DATA2


def response_app(request):
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    if request['path'] == ['foo']:
        body = request['rgi.ResponseBody']([DATA1, DATA2], len(DATA))
    elif request['path'] == ['bar']:
        body = request['rgi.ResponseBody']([b'', b''], 0)
    else:
        return (404, 'Not Found', {}, None)
    headers = {'content-length': body.content_length}
    return (200, 'OK', headers, body)


def timeout_app(request):
    assert request['method'] == 'POST'
    assert request['script'] == []
    assert request['body'] is None
    if request['path'] == ['foo']:
        # Used to test timeout on server side:
        return (200, 'OK', {}, None)
    if request['path'] == ['bar']:
        # Used to test timeout on client side:
        time.sleep(CLIENT_SOCKET_TIMEOUT + 2)
        return (200, 'OK', {}, None)
    return (404, 'Not Found', {}, None)


class TestLiveServer(TestCase):
    def build_with_app(self, build_func, *build_args):
        httpd = TempServer(degu.IPv6_LOOPBACK, build_func, *build_args)
        return (httpd, httpd.get_client())
  
    def test_chunked_request(self):
        (httpd, client) = self.build_with_app(None, chunked_request_app)

        body = base.ChunkedOutput(CHUNKS)
        response = client.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 352, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(chunk).hexdigest() for chunk in CHUNKS]
        )

        body = base.ChunkedOutput([b''])
        response = client.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 44, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(b'').hexdigest()]
        )

        body = base.ChunkedOutput(CHUNKS)
        response = client.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 352, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(chunk).hexdigest() for chunk in CHUNKS]
        )

    def test_chunked_response(self):
        (httpd, client) = self.build_with_app(None, chunked_response_app)

        response = client.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedInput)
        self.assertEqual(tuple(response.body), CHUNKS)

        response = client.request('GET', '/bar')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedInput)
        self.assertEqual(list(response.body), [b''])

        response = client.request('GET', '/baz')
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = client.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedInput)
        self.assertEqual(tuple(response.body), CHUNKS)

    def test_response(self):
        (httpd, client) = self.build_with_app(None, response_app)

        response = client.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(response.body.read(), DATA)

        response = client.request('GET', '/bar')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 0})
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(response.body.read(), b'')

        response = client.request('GET', '/baz')
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = client.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.Input)
        self.assertEqual(response.body.read(), DATA)

    def test_timeout(self):
        (httpd, client) = self.build_with_app(None, timeout_app)
        self.assertEqual(client.request('POST', '/foo'), (200, 'OK', {}, None))
        time.sleep(server.SERVER_SOCKET_TIMEOUT + 2)
        with self.assertRaises(base.EmptyLineError) as cm:
            client.request('POST', '/foo')
        self.assertIsNone(client.conn)
        self.assertIsNone(client.response_body)
        self.assertEqual(client.request('POST', '/foo'), (200, 'OK', {}, None))


def ssl_app(request):
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    assert request['ssl_cipher'] == ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    assert request['ssl_compression'] is None
    return (200, 'OK', {}, None)


class TestLiveSSLServer(TestLiveServer):
    def build_with_app(self, build_func, *build_args):
        pki = TempPKI(client_pki=True)
        httpd = TempSSLServer(pki, degu.IPv6_LOOPBACK, build_func, *build_args)
        return (httpd, httpd.get_client())

    def test_ssl(self):
        pki = TempPKI(client_pki=True)
        httpd = TempSSLServer(pki, degu.IPv6_LOOPBACK, None, ssl_app)
        server_config = pki.get_server_config()
        client_config = pki.get_client_config()

        # Test from a non-SSL client:
        client = Client(httpd.address)
        with self.assertRaises(ConnectionResetError) as cm:
            client.request('GET', '/')
        self.assertEqual(str(cm.exception), '[Errno 104] Connection reset by peer')
        self.assertIsNone(client.conn)
        self.assertIsNone(client.response_body)

        # Test with no client cert:
        client = httpd.get_client({'ca_file': client_config['ca_file']})
        with self.assertRaises(ssl.SSLError) as cm:
            client.request('GET', '/')
        self.assertTrue(
            str(cm.exception).startswith('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]')
        )
        self.assertIsNone(client.conn)
        self.assertIsNone(client.response_body)

        # Test with the wrong client cert (not signed by client CA):
        client = httpd.get_client({
            'ca_file': client_config['ca_file'],
            'cert_file': server_config['cert_file'],
            'key_file': server_config['key_file'],
        })
        with self.assertRaises(ssl.SSLError) as cm:
            client.request('GET', '/')
        self.assertTrue(
            str(cm.exception).startswith('[SSL: TLSV1_ALERT_UNKNOWN_CA]')
        )
        self.assertIsNone(client.conn)
        self.assertIsNone(client.response_body)

        # Test with a properly configured SSLClient:
        client = httpd.get_client()
        response = client.request('GET', '/')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertIsNone(response.body)

        # Test when check_hostname is True:
        client.close()
        client.sslctx.check_hostname = True
        with self.assertRaises(ssl.CertificateError) as cm:
            client.request('GET', '/')


class TestLiveServerUnixSocket(TestLiveServer):
    def build_with_app(self, build_func, *build_args):
        tmp = TempDir()
        filename = tmp.join('my.socket')
        httpd = TempServer(filename, build_func, *build_args)
        httpd._tmp = tmp
        return (httpd, httpd.get_client())

    def test_timeout(self):
        self.skipTest('FIXME')

