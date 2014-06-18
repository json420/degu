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
import io
import stat
import time
from random import SystemRandom
import socket
import ssl
import json
from hashlib import sha1

from .helpers import TempDir, DummySocket, DummyFile
import degu
from degu import util
from degu.sslhelpers import random_id
from degu.misc import TempPKI, TempServer, TempSSLServer
from degu.client import Client, SSLClient, build_client_sslctx
from degu.base import TYPE_ERROR
from degu import base, server


random = SystemRandom()


def standard_harness_app(session, request):
    if len(request['path']) == 3 and request['path'][0] == 'status':
        code = int(request['path'][1])
        reason = request['path'][2]
        return (code, reason, {}, None)


class TestFunctions(TestCase):
    def test_build_server_sslctx(self):
        # Bad config type:
        with self.assertRaises(TypeError) as cm:
            server.build_server_sslctx('bad')
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('config', dict, str, 'bad')
        )

        # Non absulute, non normalized paths:
        good = {
            'cert_file': '/my/server.cert',
            'key_file': '/my/server.key',
            'ca_file': '/my/client.ca',
            'ca_path': '/my/client.ca.dir',
        }
        for key in good.keys():
            # Relative path:
            bad = good.copy()
            value = 'relative/path'
            bad[key] = value
            with self.assertRaises(ValueError) as cm:
                server.build_server_sslctx(bad)
            self.assertEqual(str(cm.exception),
                'config[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
            )
            # Non-normalized path with directory traversal:
            bad = good.copy()
            value = '/my/../secret/path'
            bad[key] = value
            with self.assertRaises(ValueError) as cm:
                server.build_server_sslctx(bad)
            self.assertEqual(str(cm.exception),
                'config[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
            )
            # Non-normalized path with trailing slash:
            bad = good.copy()
            value = '/sorry/very/strict/'
            bad[key] = value
            with self.assertRaises(ValueError) as cm:
                server.build_server_sslctx(bad)
            self.assertEqual(str(cm.exception),
                'config[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
            )


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
        config['ca_file'] = '/my/client.ca'
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

    def test_validate_server_sslctx(self):
        # Bad type:
        with self.assertRaises(TypeError) as cm:
            server.validate_server_sslctx(ssl.SSLContext)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Wrong protocol:
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(ssl.SSLContext(ssl.PROTOCOL_TLSv1))
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.PROTOCOL_TLSv1_2'
        )

        # Don't allow ssl.CERT_OPTIONAL:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.verify_mode = ssl.CERT_OPTIONAL
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.verify_mode cannot be ssl.CERT_OPTIONAL'
        )

        # options missing OP_NO_COMPRESSION:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.assertIs(sslctx.verify_mode, ssl.CERT_NONE)
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # options missing OP_SINGLE_ECDH_USE:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_SINGLE_ECDH_USE'
        )

        # options missing OP_CIPHER_SERVER_PREFERENCE:
        sslctx.options |= ssl.OP_SINGLE_ECDH_USE
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE'
        )

        # All good:
        sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        self.assertIs(server.validate_server_sslctx(sslctx), sslctx)

        # Now again, this time with CERT_REQUIRED:
        # options missing OP_NO_COMPRESSION:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.verify_mode = ssl.CERT_REQUIRED
        self.assertIs(sslctx.verify_mode, ssl.CERT_REQUIRED)
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # options missing OP_SINGLE_ECDH_USE:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_SINGLE_ECDH_USE'
        )

        # options missing OP_CIPHER_SERVER_PREFERENCE:
        sslctx.options |= ssl.OP_SINGLE_ECDH_USE
        with self.assertRaises(ValueError) as cm:
            server.validate_server_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE'
        )

        # All good:
        sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        self.assertIs(server.validate_server_sslctx(sslctx), sslctx)

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

        # Bad method:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('OPTIONS /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad HTTP method: 'OPTIONS'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('get /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(str(cm.exception), "bad HTTP method: 'get'")

        # Bad protocol:
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk HTTP/1.0')
        self.assertEqual(str(cm.exception), "bad HTTP protocol: 'HTTP/1.0'")
        with self.assertRaises(ValueError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk HTTP/2.0')
        self.assertEqual(str(cm.exception), "bad HTTP protocol: 'HTTP/2.0'")

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

        # Test all valid methods:
        for M in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD'):
            line = '{} /foo/bar?stuff=junk HTTP/1.1'.format(M)
            (method, path_list, query) = server.parse_request(line)
            self.assertEqual(method, M)
            self.assertEqual(path_list, ['foo', 'bar'])
            self.assertEqual(query, 'stuff=junk')

        # Test URI permutations and round-tripping with util.relative_uri():
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
                request = {'path': path_list, 'query': query}
                self.assertEqual(util.relative_uri(request), uri)

        # Test URI with a trailing "?" but no query (note that relative_uri()
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

        # isinstance(body, Body):
        body = base.Body(io.BytesIO(), 5)
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

        # isinstance(body, ChunkedBody):
        body = base.ChunkedBody(io.BytesIO())
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

    def test_read_request(self):
        longline = (b'D' * (base.MAX_LINE_BYTES - 1)) + b'\r\n'

        # No data:
        rfile = io.BytesIO()
        with self.assertRaises(base.EmptyPreambleError):
            server.read_request(rfile)

       # CRLF terminated request line is empty: 
        rfile = io.BytesIO(b'\r\n')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), 'first preamble line is empty')
        self.assertEqual(rfile.tell(), 2)
        self.assertEqual(rfile.read(), b'')

        # Line too long:
        rfile = io.BytesIO(longline)
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b'D\\r'")
        self.assertEqual(rfile.tell(), base.MAX_LINE_BYTES)
        self.assertEqual(rfile.read(), b'\n')

        # LF but no proceeding CR:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\n\r\n')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b'1\\n'")
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(rfile.read(), b'\r\n')

        # Missing CRLF preamble terminator:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\n')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b''")
        self.assertEqual(rfile.tell(), 19)
        self.assertEqual(rfile.read(), b'')

        # 1st header line too long:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\n' + longline)
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b'D\\r'")
        self.assertEqual(rfile.tell(), base.MAX_LINE_BYTES + 19)
        self.assertEqual(rfile.read(), b'\n')

        # 1st header line has LF but no proceeding CR:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\nBar: baz\n\r\n')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b'z\\n'")
        self.assertEqual(rfile.tell(), 28)
        self.assertEqual(rfile.read(), b'\r\n')

        # Again, missing CRLF preamble terminator, but with a header also:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\nBar: baz\r\n')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b''")
        self.assertEqual(rfile.tell(), 29)
        self.assertEqual(rfile.read(), b'')

        # Request line has too few items to split:
        rfile = io.BytesIO(b'GET /fooHTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), 'need more than 2 values to unpack')
        self.assertEqual(rfile.tell(), 20)
        self.assertEqual(rfile.read(), b'body')

        # Request line has too many items to split:
        rfile = io.BytesIO(b'GET /f\roo HTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 3)'
        )
        self.assertEqual(rfile.tell(), 22)
        self.assertEqual(rfile.read(), b'body')

        # Bad method:
        rfile = io.BytesIO(b'OPTIONS /foo HTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad HTTP method: 'OPTIONS'")
        self.assertEqual(rfile.tell(), 25)
        self.assertEqual(rfile.read(), b'body')

        # Bad protocol:
        rfile = io.BytesIO(b'GET /foo HTTP/1.0\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad HTTP protocol: 'HTTP/1.0'")
        self.assertEqual(rfile.tell(), 21)
        self.assertEqual(rfile.read(), b'body')

        # Too many ? in uri:
        rfile = io.BytesIO(b'GET /foo?bar=baz?stuff=junk HTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            "bad request uri: '/foo?bar=baz?stuff=junk'"
        )
        self.assertEqual(rfile.tell(), 40)
        self.assertEqual(rfile.read(), b'body')

        # uri path doesn't start with /:
        rfile = io.BytesIO(b'GET foo/bar?baz HTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad request path: 'foo/bar'")
        self.assertEqual(rfile.tell(), 28)
        self.assertEqual(rfile.read(), b'body')

        # uri path contains a double //:
        rfile = io.BytesIO(b'GET /foo//bar?baz HTTP/1.1\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), "bad request path: '/foo//bar'")
        self.assertEqual(rfile.tell(), 30)
        self.assertEqual(rfile.read(), b'body')

        # 1st header line has too few items to split:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\nBar:baz\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception), 'need more than 1 value to unpack')
        self.assertEqual(rfile.tell(), 30)
        self.assertEqual(rfile.read(), b'body')

        # 1st header line has too many items to split:
        rfile = io.BytesIO(b'GET /foo HTTP/1.1\r\nBar: baz: jazz\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 2)'
        )
        self.assertEqual(rfile.tell(), 37)
        self.assertEqual(rfile.read(), b'body')

        # Duplicate headers:
        rfile = io.BytesIO(b'GET / HTTP/1.1\r\nFoo: bar\r\nfoo: baz\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            'duplicates in header_lines:\n  Foo: bar\n  foo: baz'
        )
        self.assertEqual(rfile.tell(), 38)
        self.assertEqual(rfile.read(), b'body')

        # Content-Length can't be parsed as a base-10 integer:
        rfile = io.BytesIO(b'GET / HTTP/1.1\r\nContent-Length: 16.9\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 10: '16.9'"
        )
        self.assertEqual(rfile.tell(), 40)
        self.assertEqual(rfile.read(), b'body')

        # Content-Length is negative:
        rfile = io.BytesIO(b'GET / HTTP/1.1\r\nContent-Length: -17\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            'negative content-length: -17'
        )
        self.assertEqual(rfile.tell(), 39)
        self.assertEqual(rfile.read(), b'body')

        # Bad Transfer-Encoding:
        rfile = io.BytesIO(b'GET / HTTP/1.1\r\nTransfer-Encoding: CHUNKED\r\n\r\nbody')
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            "bad transfer-encoding: 'CHUNKED'"
        )
        self.assertEqual(rfile.tell(), 46)
        self.assertEqual(rfile.read(), b'body')

        # Content-Length with Transfer-Encoding:
        rfile = io.BytesIO(
            b'GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 17\r\n\r\nbody'
        )
        with self.assertRaises(ValueError) as cm:
            server.read_request(rfile)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        self.assertEqual(rfile.tell(), 66)
        self.assertEqual(rfile.read(), b'body')

        # No headers, no body, no query:
        rfile = io.BytesIO(b'GET / HTTP/1.1\r\n\r\nextra')
        self.assertEqual(server.read_request(rfile),
            {
                'method': 'GET',
                'script': [],
                'path': [],
                'query': '',
                'headers': {},
                'body': None,
            }
        )
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(rfile.read(), b'extra')

        # No headers, no body, but add a query:
        rfile = io.BytesIO(b'HEAD /foo?nonpair HTTP/1.1\r\n\r\nextra')
        self.assertEqual(server.read_request(rfile),
            {
                'method': 'HEAD',
                'script': [],
                'path': ['foo'],
                'query': 'nonpair',
                'headers': {},
                'body': None,
            }
        )
        self.assertEqual(rfile.tell(), 30)
        self.assertEqual(rfile.read(), b'extra')

        # Add a header, still no body:
        rfile = io.BytesIO(
            b'DELETE /foo/Bar/?keY=vAl HTTP/1.1\r\nME: YOU\r\n\r\nextra'
        )
        self.assertEqual(server.read_request(rfile),
            {
                'method': 'DELETE',
                'script': [],
                'path': ['foo', 'Bar', ''],
                'query': 'keY=vAl',
                'headers': {'me': 'YOU'},
                'body': None,
            }
        )
        self.assertEqual(rfile.tell(), 46)
        self.assertEqual(rfile.read(), b'extra')

    def test_read_request_fuzz(self):
        """
        Random fuzz test for read_request().

        Expected result: given an rfile containing 8192 random bytes,
        read_request() should raise a ValueError every time, and should never
        read more than the first 4096 bytes.
        """
        for i in range(1000):
            data = os.urandom(base.MAX_LINE_BYTES * 2)
            rfile = io.BytesIO(data)
            with self.assertRaises(ValueError):
                server.read_request(rfile)
            self.assertLessEqual(rfile.tell(), base.MAX_LINE_BYTES)

    def test_write_response(self):
        # Empty headers, no body:
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', {}, None),
            19
        )
        self.assertEqual(wfile.tell(), 19)
        self.assertEqual(wfile.getvalue(), b'HTTP/1.1 200 OK\r\n\r\n')

        # One header:
        headers = {'foo': 17}  # Make sure to test with int header value
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, None),
            28
        )
        self.assertEqual(wfile.tell(), 28)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        headers = {'foo': 17, 'bar': 'baz'}
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, None),
            38
        )
        self.assertEqual(wfile.tell(), 38)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, b'hello'),
            43
        )
        self.assertEqual(wfile.tell(), 43)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\nhello'
        )

        # body is bytearray:
        body = bytearray(b'hello')
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, body),
            43
        )
        self.assertEqual(wfile.tell(), 43)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\nhello'
        )

        # body is base.Body:
        rfile = io.BytesIO(b'hello')
        body = base.Body(rfile, 5)
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, body),
            43
        )
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(wfile.tell(), 43)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = base.ChunkedBody(rfile)
        wfile = io.BytesIO()
        self.assertEqual(
            server.write_response(wfile, 200, 'OK', headers, body),
            53
        )
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(wfile.tell(), 53)
        self.assertEqual(wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )


class TestHandler(TestCase):
    def test_init(self):
        app = random_id()
        sock = DummySocket()
        session = random_id()
        handler = server.Handler(app, sock, session)
        self.assertIs(handler.closed, False)
        self.assertIs(handler.app, app)
        self.assertIs(handler.session, session)
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
        self.assertIsInstance(body, base.Body)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.remaining, 17)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.read(), data)
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
        self.assertIsInstance(body, base.ChunkedBody)
        self.assertIs(body.rfile, fp)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.readchunk(), (chunk1, None))
        self.assertEqual(body.readchunk(), (chunk2, None))
        self.assertEqual(body.readchunk(), (b'', None))
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)


class BadApp:
    """
    Not callable.
    """


def good_app(session, request):
    return (200, 'OK', {}, None)


class BadConnectionHandler:
    def __call__(self, session, request):
        pass

    on_connect = 'nope'


class GoodConnectionHandler:
    def __call__(self, session, request):
        pass

    def on_connect(self, sock, session):
        pass


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
        self.assertEqual(inst.scheme, 'http')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, app)
        self.assertEqual(inst.on_connect, app.on_connect)

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

    def test_build_base_session(self):
        class ServerSubclass(server.Server):
            def __init__(self, address):
                self.address = address

        address = (random_id(), random_id())
        inst = ServerSubclass(address)
        self.assertEqual(inst.build_base_session(), {
            'scheme': 'http',
            'protocol': 'HTTP/1.1',
            'server': address,
            'rgi.Body': base.Body,
            'rgi.ChunkedBody': base.ChunkedBody,
            'requests': 0,
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
        self.assertEqual(inst.scheme, 'https')
        self.assertIsInstance(inst.sock, socket.socket)
        port = inst.sock.getsockname()[1]
        self.assertEqual(inst.address, ('::1', port, 0, 0))
        self.assertIs(inst.app, app)
        self.assertEqual(inst.on_connect, app.on_connect)

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

    def test_build_base_session(self):
        class SSLServerSubclass(server.SSLServer):
            def __init__(self, address):
                self.address = address

        address = (random_id(), random_id())
        inst = SSLServerSubclass(address)
        self.assertEqual(inst.build_base_session(), {
            'scheme': 'https',
            'protocol': 'HTTP/1.1',
            'server': address,
            'rgi.Body': base.Body,
            'rgi.ChunkedBody': base.ChunkedBody,
            'requests': 0,
        })


CHUNKS = []
for i in range(7):
    size = random.randint(1, 5000)
    CHUNKS.append(os.urandom(size))
CHUNKS.append(b'')
CHUNKS = tuple(CHUNKS)
wfile = io.BytesIO()
for data in CHUNKS:
    base.write_chunk(wfile, data)
ENCODED_CHUNKS = wfile.getvalue()
del wfile


def chunked_request_app(session, request):
    assert request['method'] == 'POST'
    assert request['script'] == []
    assert request['path'] == []
    assert isinstance(request['body'], base.ChunkedBody)
    assert request['headers']['transfer-encoding'] == 'chunked'
    result = []
    for (data, extension) in request['body']:
        result.append(sha1(data).hexdigest())
    body = json.dumps(result).encode('utf-8')
    headers = {'content-length': len(body), 'content-type': 'application/json'}
    return (200, 'OK', headers, body)


def chunked_response_app(session, request):
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    headers = {'transfer-encoding': 'chunked'}
    if request['path'] == ['foo']:
        rfile = io.BytesIO(ENCODED_CHUNKS)
    elif request['path'] == ['bar']:
        rfile = io.BytesIO(b'0\r\n\r\n')
    else:
        return (404, 'Not Found', {}, None)
    body = session['rgi.ChunkedBody'](rfile)
    return (200, 'OK', headers, body)


DATA1 = os.urandom(1776)
DATA2 = os.urandom(3469)
DATA = DATA1 + DATA2


def response_app(session, request):
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    if request['path'] == ['foo']:
        body = session['rgi.Body'](io.BytesIO(DATA), len(DATA))
    elif request['path'] == ['bar']:
        body = session['rgi.Body'](io.BytesIO(), 0)
    else:
        return (404, 'Not Found', {}, None)
    headers = {'content-length': body.content_length}
    return (200, 'OK', headers, body)


def timeout_app(session, request):
    assert request['method'] == 'POST'
    assert request['script'] == []
    assert request['body'] is None
    if request['path'] == ['foo']:
        # Used to test timeout on server side:
        return (200, 'OK', {}, None)
    if request['path'] == ['bar']:
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

    def __call__(self, session, request):
        return (200, 'OK', {}, self.marker)

    def on_connect(self, sock, session):
        return self.accept


class TestLiveServer(TestCase):
    address = degu.IPv4_LOOPBACK

    def build_with_app(self, build_func, *build_args):
        httpd = TempServer(self.address, build_func, *build_args)
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
        if os.environ.get('DEGU_TEST_SKIP_SLOW') == 'true':
            self.skipTest('skipping as DEGU_TEST_SKIP_SLOW is set')
        (httpd, client) = self.build_with_app(None, timeout_app)
        conn = client.connect()

        # Make an inital request:
        self.assertEqual(conn.request('POST', '/foo'), (200, 'OK', {}, None))

        # Wait till 1 second *before* the timeout should happen, to make sure
        # connection is still open:
        time.sleep(server.SERVER_SOCKET_TIMEOUT - 1)
        self.assertEqual(conn.request('POST', '/foo'), (200, 'OK', {}, None))

        # Now tait till 1 second *after* the timeout should have happened, to
        # make sure the connection was closed by the server:
        time.sleep(server.SERVER_SOCKET_TIMEOUT + 1)
        with self.assertRaises(ConnectionError):
            conn.request('POST', '/foo')
        self.assertIs(conn.closed, True)
        self.assertIsNone(conn.sock)
        conn = client.connect()
        self.assertEqual(conn.request('POST', '/foo'), (200, 'OK', {}, None))
        httpd.terminate()

    def test_chunked_request(self):
        (httpd, client) = self.build_with_app(None, chunked_request_app)
        conn = client.connect()

        body = base.ChunkedBody(io.BytesIO(ENCODED_CHUNKS))
        response = conn.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 352, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.Body)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(chunk).hexdigest() for chunk in CHUNKS]
        )

        body = base.ChunkedBody(io.BytesIO(b'0\r\n\r\n'))
        response = conn.request('POST', '/', {}, body)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers,
            {'content-length': 44, 'content-type': 'application/json'}
        )
        self.assertIsInstance(response.body, base.Body)
        self.assertEqual(json.loads(response.body.read().decode('utf-8')),
            [sha1(b'').hexdigest()]
        )

        httpd.terminate()

    def test_chunked_response(self):
        (httpd, client) = self.build_with_app(None, chunked_response_app)
        conn = client.connect()

        response = conn.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedBody)
        self.assertEqual(tuple(response.body),
            tuple((data, None) for data in CHUNKS)
        )

        response = conn.request('GET', '/bar')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedBody)
        self.assertEqual(list(response.body), [(b'', None)])

        response = conn.request('GET', '/baz')
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = conn.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, base.ChunkedBody)
        self.assertEqual(tuple(response.body),
            tuple((data, None) for data in CHUNKS)
        )
        httpd.terminate()

    def test_response(self):
        (httpd, client) = self.build_with_app(None, response_app)
        conn = client.connect()

        response = conn.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.Body)
        self.assertEqual(response.body.read(), DATA)

        response = conn.request('GET', '/bar')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 0})
        self.assertIsInstance(response.body, base.Body)
        self.assertEqual(response.body.read(), b'')

        response = conn.request('GET', '/baz')
        self.assertEqual(response.status, 404)
        self.assertEqual(response.reason, 'Not Found')
        self.assertEqual(response.headers, {})
        self.assertIsNone(response.body)

        response = conn.request('GET', '/foo')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': len(DATA)})
        self.assertIsInstance(response.body, base.Body)
        self.assertEqual(response.body.read(), DATA)
        httpd.terminate()

    def test_always_accept_connections(self):
        marker = os.urandom(16)
        app = AppWithConnectionHandler(marker, True)
        (httpd, client) = self.build_with_app(None, app)
        for i in range(17):
            conn = client.connect()
            for j in range(69):
                response = conn.request('GET', '/')
                self.assertEqual(response.status, 200)
                self.assertEqual(response.reason, 'OK')
                self.assertEqual(response.headers, {'content-length': 16})
                self.assertIsInstance(response.body, base.Body)
                self.assertEqual(response.body.read(), marker)
            conn.close()
        httpd.terminate()

    def test_always_reject_connections(self):
        marker = os.urandom(16)
        app = AppWithConnectionHandler(marker, False)
        (httpd, client) = self.build_with_app(None, app)
        for i in range(17):
            conn = client.connect()
            with self.assertRaises(ConnectionError):
                conn.request('GET', '/')
            self.assertIs(conn.closed, True)
            self.assertIsNone(conn.sock)
        httpd.terminate()

    def test_ok_status(self):
        (httpd, client) = self.build_with_app(None, standard_harness_app)
        conn = client.connect()
        # At no point should the connection be closed by the server:
        for status in range(100, 400):
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            response = conn.request('GET', uri)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
            # Again with a 2nd random reason string:
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            response = conn.request('GET', uri)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
        conn.close() 
        httpd.terminate()

    def test_error_status(self):
        (httpd, client) = self.build_with_app(None, standard_harness_app)
        for status in range(400, 600):
            reason = random_id()
            uri = '/status/{}/{}'.format(status, reason)
            conn = client.connect()
            response = conn.request('GET', uri)
            self.assertEqual(response.status, status)
            self.assertEqual(response.reason, reason)
            self.assertEqual(response.headers, {})
            self.assertIsNone(response.body)
            if status in {404, 409, 412}:
                # Connection should not be closed for 404, 409, 412:
                response = conn.request('GET', uri)
                self.assertEqual(response.status, status)
                self.assertEqual(response.reason, reason)
                self.assertEqual(response.headers, {})
                self.assertIsNone(response.body)
                conn.close()
            else:
                # But connection should be closed for all other status >= 400:
                with self.assertRaises(ConnectionError):
                    conn.request('GET', uri)
                self.assertIs(conn.closed, True)
                self.assertIsNone(conn.sock)
        httpd.terminate()


class TestLiveServer_AF_INET6(TestLiveServer):
    address = degu.IPv6_LOOPBACK


class TestLiveServer_AF_UNIX(TestLiveServer):
    def build_with_app(self, build_func, *build_args):
        tmp = TempDir()
        filename = tmp.join('my.socket')
        httpd = TempServer(filename, build_func, *build_args)
        httpd.tmp = tmp
        return (httpd, Client(httpd.address))


def ssl_app(session, request):
    assert session['ssl_cipher'] == (
        'ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256
    )
    assert session['ssl_compression'] is None
    assert request['method'] == 'GET'
    assert request['script'] == []
    assert request['body'] is None
    return (200, 'OK', {}, None)


class TestLiveSSLServer(TestLiveServer):
    def build_with_app(self, build_func, *build_args):
        pki = TempPKI()
        httpd = TempSSLServer(
            pki.get_server_config(), self.address, build_func, *build_args
        )
        httpd.pki = pki
        sslctx = build_client_sslctx(pki.get_client_config())
        return (httpd, SSLClient(sslctx, httpd.address))

    def test_ssl(self):
        pki = TempPKI(client_pki=True)
        server_config = pki.get_server_config()
        client_config = pki.get_client_config()
        httpd = TempSSLServer(server_config, self.address, None, ssl_app)

        # Test from a non-SSL client:
        client = Client(httpd.address)
        conn = client.connect()
        with self.assertRaises(ConnectionResetError) as cm:
            conn.request('GET', '/')
        self.assertEqual(str(cm.exception), '[Errno 104] Connection reset by peer')
        self.assertIs(conn.closed, True)
        self.assertIsNone(conn.response_body)

        # Test with no client cert:
        sslctx = build_client_sslctx({'ca_file': client_config['ca_file']})
        client = SSLClient(sslctx, httpd.address)
        with self.assertRaises(ssl.SSLError) as cm:
            client.connect()
        self.assertTrue(
            str(cm.exception).startswith('[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]')
        )
        self.assertIs(conn.closed, True)
        self.assertIsNone(conn.response_body)

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
        self.assertIsNone(conn.response_body)

        # Test with a properly configured SSLClient:
        sslctx = build_client_sslctx(client_config)
        client = SSLClient(sslctx, httpd.address)
        conn = client.connect()
        response = conn.request('GET', '/')
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

