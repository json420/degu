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
import socket
import ssl

from .helpers import TempDir, DummySocket, DummyFile
from degu.misc import TempPKI
from degu import base, client


class TestNamedTuples(TestCase):
    def test_Connection(self):
        tup = client.Connection('da sock', 'da rfile', 'da wfile')
        self.assertIsInstance(tup, tuple)
        self.assertEqual(tup.sock, 'da sock')
        self.assertEqual(tup.rfile, 'da rfile')
        self.assertEqual(tup.wfile, 'da wfile')

    def test_Response(self):
        tup = client.Response('da status', 'da reason', 'da headers', 'da body')
        self.assertIsInstance(tup, tuple)
        self.assertEqual(tup.status, 'da status')
        self.assertEqual(tup.reason, 'da reason')
        self.assertEqual(tup.headers, 'da headers')
        self.assertEqual(tup.body, 'da body')


class TestFunctions(TestCase):
    def test_build_client_sslctx(self):
        # Empty config, will verify against system-wide CAs:
        sslctx = client.build_client_sslctx({})
        self.assertIsNone(base.validate_sslctx(sslctx))
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)

        # client_pki=False:
        pki = TempPKI()
        sslctx = client.build_client_sslctx(pki.client_config)
        self.assertIsNone(base.validate_sslctx(sslctx))
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)

        # client_pki=True:
        pki = TempPKI(client_pki=True)
        sslctx = client.build_client_sslctx(pki.client_config)
        self.assertIsNone(base.validate_sslctx(sslctx))
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)

    def test_validate_request(self):
        # Bad method:
        with self.assertRaises(ValueError) as cm:
            client.validate_request('get', None, None, None)
        self.assertEqual(str(cm.exception), "invalid method: 'get'")

        # Bad uri:
        with self.assertRaises(ValueError) as cm:
            client.validate_request('GET', 'foo', None, None)
        self.assertEqual(str(cm.exception), "bad uri: 'foo'")

        # Non-casefolded header name:
        H = {'Content-Type': 'text/plain'}
        with self.assertRaises(ValueError) as cm:
            client.validate_request('GET', '/foo', H, None)
        self.assertEqual(str(cm.exception),
            "non-casefolded header name: 'Content-Type'"
        )

        # Bad body type:
        H = {'content-type': 'text/plain'}
        with self.assertRaises(TypeError) as cm:
            client.validate_request('GET', '/foo', H, 'hello')
        self.assertEqual(str(cm.exception),
            "bad request body type: <class 'str'>"
        )

        # Both content-length and transfer-encoding present:
        H = {'content-length': 17, 'transfer-encoding': 'chunked'}
        with self.assertRaises(ValueError) as cm:
            client.validate_request('GET', '/foo', H, None)
        self.assertEqual(str(cm.exception),
            'content-length with transfer-encoding'
        )

        # content-length with a None body:
        H = {'content-length': 17}
        with self.assertRaises(ValueError) as cm:
            client.validate_request('GET', '/foo', H, None)
        self.assertEqual(str(cm.exception),
            "cannot include 'content-length' when body is None"
        )

        # transfer-encoding with a None body:
        H = {'transfer-encoding': 'chunked'}
        with self.assertRaises(ValueError) as cm:
            client.validate_request('GET', '/foo', H, None)
        self.assertEqual(str(cm.exception),
            "cannot include 'transfer-encoding' when body is None"
        )

        # Cannot include body in GET, HEAD, DELETE:
        for M in ('GET', 'HEAD', 'DELETE'):
            with self.assertRaises(ValueError) as cm:
                client.validate_request(M, '/foo', {}, b'hello')
            self.assertEqual(str(cm.exception),
                'cannot include body in a {} request'.format(M)
            )

        # No in-place header modification should happen with GET, HEAD, DELETE:
        for M in ('GET', 'HEAD', 'DELETE'):
            H = {}
            self.assertIsNone(client.validate_request(M, '/foo', H, None))
            self.assertEqual(H, {})

        # Test with all the non-chunked body types:
        tmp = TempDir()
        fp = tmp.prepare(b'')  # Contents of rfile wont matter
        bodies = (
            os.urandom(17),
            bytearray(os.urandom(17)),
            base.Output([], 17),
            base.FileOutput(fp, 17),
        )
        for M in ('PUT', 'POST'):
            for B in bodies:
                H = {}
                self.assertIsNone(client.validate_request(M, '/foo', H, B))
                self.assertEqual(H, {'content-length': 17})

        # Finally test with base.ChunkedOutput:
        B = base.ChunkedOutput([b''])
        for M in ('PUT', 'POST'):
            H = {}
            self.assertIsNone(client.validate_request(M, '/foo', H, B))
            self.assertEqual(H, {'transfer-encoding': 'chunked'})

    def test_iter_request_lines(self):
        # Test when headers is an empty dict:
        self.assertEqual(
            list(client.iter_request_lines('GET', '/dmedia-1', {})),
            [
                'GET /dmedia-1 HTTP/1.1\r\n',
                '\r\n',
            ]
        )    

        # Should also work when headers is None:
        self.assertEqual(
            list(client.iter_request_lines('GET', '/dmedia-1', None)),
            [
                'GET /dmedia-1 HTTP/1.1\r\n',
                '\r\n',
            ]
        )

        # Test when headers is non-empty:
        headers = {
            'accept': 'application/json',
            'user-agent': 'foo',
            'content-length': 1776,
            'content-type': 'application/json',
            'authorization': 'blah blah',
        }
        self.assertEqual(
            list(client.iter_request_lines('GET', '/dmedia-1', headers)),
            [
                'GET /dmedia-1 HTTP/1.1\r\n',
                'accept: application/json\r\n',
                'authorization: blah blah\r\n',
                'content-length: 1776\r\n',
                'content-type: application/json\r\n',
                'user-agent: foo\r\n',
                '\r\n',
            ]
        )

    def test_parse_status(self):
        # Not enough spaces:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200OK')
        self.assertEqual(cm.exception.reason, 'Bad Status Line')

        # Bad protocol:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.0 200 OK')
        self.assertEqual(cm.exception.reason, 'HTTP Version Not Supported')

        # Status not an int:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 17.9 OK')
        self.assertEqual(cm.exception.reason, 'Bad Status Code')

        # Status outside valid range:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 99 OK')
        self.assertEqual(cm.exception.reason, 'Invalid Status Code')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 600 OK')
        self.assertEqual(cm.exception.reason, 'Invalid Status Code')

        # Empty reason:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200 ')
        self.assertEqual(cm.exception.reason, 'Empty Reason')

        # Leading or trailing whitespace in reason:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  Okey Dokey')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200 Okey Dokey ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  OK ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')

        # A gew good static values:
        self.assertEqual(client.parse_status('HTTP/1.1 200 OK'),
            (200, 'OK')
        )
        self.assertEqual(client.parse_status('HTTP/1.1 404 Not Found'),
            (404, 'Not Found')
        )
        self.assertEqual(client.parse_status('HTTP/1.1 505 HTTP Version Not Supported'),
            (505, 'HTTP Version Not Supported')
        )

        # Go through a bunch O permutations:
        for i in range(100, 600):
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo'.format(i)),
                (i, 'Foo')
            )
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo Bar'.format(i)),
                (i, 'Foo Bar')
            )
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo Bar Baz'.format(i)),
                (i, 'Foo Bar Baz')
            )

    def test_read_response(self):
        tmp = TempDir()

        # No headers, no body:
        lines = ''.join([
            'HTTP/1.1 200 OK\r\n',
            '\r\n',
        ]).encode('latin_1')
        rfile = tmp.prepare(lines)
        r = client.read_response(rfile, 'GET')
        self.assertIsInstance(r, client.Response)
        self.assertEqual(r, (200, 'OK', {}, None))

        # Content-Length, body should be base.Input:
        lines = ''.join([
            'HTTP/1.1 200 OK\r\n',
            'Content-Length: 17\r\n',
            '\r\n',
        ]).encode('latin_1')
        data = os.urandom(17)
        rfile = tmp.prepare(lines + data)
        r = client.read_response(rfile, 'GET')
        self.assertIsInstance(r, client.Response)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'content-length': 17})
        self.assertIsInstance(r.body, base.Input)
        self.assertIs(r.body.rfile, rfile)
        self.assertIs(r.body.closed, False)
        self.assertEqual(r.body.remaining, 17)
        self.assertEqual(rfile.tell(), len(lines))
        self.assertEqual(r.body.read(), data)
        self.assertEqual(rfile.tell(), len(lines) + len(data))
        self.assertIs(r.body.closed, True)
        self.assertEqual(r.body.remaining, 0)

        # Like above, except this time for a HEAD request:
        rfile = tmp.prepare(lines + data)
        r = client.read_response(rfile, 'HEAD')
        self.assertIsInstance(r, client.Response)
        self.assertEqual(r, (200, 'OK', {'content-length': 17}, None))

        # Transfer-Encoding, body should be base.ChunkedInput:
        lines = ''.join([
            'HTTP/1.1 200 OK\r\n',
            'Transfer-Encoding: chunked\r\n',
            '\r\n',
        ]).encode('latin_1')
        chunk1 = os.urandom(21)
        chunk2 = os.urandom(17)
        chunk3 = os.urandom(19)
        (filename, fp) = tmp.create('foo')
        fp.write(lines)
        total = 0
        for chunk in [chunk1, chunk2, chunk3, b'']:
            total += base.write_chunk(fp, chunk)
        fp.close()
        rfile = open(filename, 'rb')
        r = client.read_response(rfile, 'GET')
        self.assertIsInstance(r, client.Response)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(r.body, base.ChunkedInput)
        self.assertIs(r.body.rfile, rfile)
        self.assertEqual(rfile.tell(), len(lines))
        self.assertIs(r.body.closed, False)
        self.assertEqual(list(r.body), [chunk1, chunk2, chunk3, b''])
        self.assertIs(r.body.closed, True)
        self.assertEqual(rfile.tell(), len(lines) + total)


class TestClient(TestCase):
    def test_init(self):
        hostname = '127.0.0.1'
        port = 5984
        inst = client.Client(hostname, port)
        self.assertIs(inst.hostname, hostname)
        self.assertIs(inst.port, port)
        self.assertIsNone(inst.conn)
        self.assertIsNone(inst.response_body)

        inst = client.Client(hostname, None)
        self.assertIs(inst.hostname, hostname)
        self.assertEqual(inst.port, 80)
        self.assertIsNone(inst.conn)
        self.assertIsNone(inst.response_body)

    def test_connect(self):
        class ClientSubclass(client.Client):
            def __init__(self, sock):
                self._sock = sock
                self.conn = None

            def create_socket(self):
                return self._sock

        sock = DummySocket()
        inst = ClientSubclass(sock)
        conn = inst.connect()
        self.assertIs(conn, inst.conn)
        self.assertIsInstance(conn, client.Connection)
        self.assertEqual(conn, (sock, sock._rfile, sock._wfile))
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

        # Should do nothing when conn is not None:
        sock._calls.clear()
        self.assertIs(inst.connect(), conn)
        self.assertIs(conn, inst.conn)
        self.assertEqual(sock._calls, [])

    def test_close(self):
        inst = client.Client('::1', None)

        # Should set response_body to None even if conn is None:
        inst.response_body = 'foo'
        self.assertIsNone(inst.close())
        self.assertIsNone(inst.response_body)
        self.assertIsNone(inst.conn)

        # Now try it when conn is not None:
        sock = DummySocket()
        rfile = DummyFile()
        wfile = DummyFile()
        conn = client.Connection(sock, rfile, wfile)
        inst.response_body = 'foo'
        inst.conn = conn
        self.assertIsNone(inst.close())
        self.assertIsNone(inst.response_body)
        self.assertIsNone(inst.conn)
        self.assertEqual(rfile._calls, ['close'])
        self.assertEqual(wfile._calls, ['close'])
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR), 'close'])

    def test_request(self):
        # Test when the previous response body wasn't consumed:
        class DummyBody:
            closed = False

        inst = client.Client('::1', None)
        inst.response_body = DummyBody
        with self.assertRaises(client.UnconsumedResponseError) as cm:
            inst.request(None, None)
        self.assertIs(cm.exception.body, DummyBody)
        self.assertEqual(str(cm.exception),
            'previous response body not consumed: {!r}'.format(DummyBody)
        )


class TestSSLClient(TestCase):
    def test_init(self):
        hostname = '127.0.0.1'
        port = 5984

        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            client.SSLClient('foo', hostname, port)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, hostname, port)
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.{}'.format(base.TLS.name)
        )

        # not (options & ssl.OP_NO_SSLv2)
        sslctx = ssl.SSLContext(base.TLS.protocol)
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, hostname, port)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_SSLv2'
        )

        # not (options & ssl.OP_NO_COMPRESSION)
        sslctx.options |= ssl.OP_NO_SSLv2
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, hostname, port)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # verify_mode is not ssl.CERT_REQUIRED:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, hostname, port)
        self.assertEqual(str(cm.exception),
            'sslctx.verify_mode must be ssl.CERT_REQUIRED'
        )

        # Good sslctx from here on:
        sslctx.verify_mode = ssl.CERT_REQUIRED
        inst = client.SSLClient(sslctx, hostname, port)
        self.assertIs(inst.hostname, hostname)
        self.assertIs(inst.port, port)
        self.assertIsNone(inst.conn)
        self.assertIsNone(inst.response_body)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.check_hostname, True)

        # Test default_port, and overriding check_hostname:
        sslctx.verify_mode = ssl.CERT_REQUIRED
        inst = client.SSLClient(sslctx, hostname, check_hostname=False)
        self.assertIs(inst.hostname, hostname)
        self.assertEqual(inst.port, 443)
        self.assertIsNone(inst.conn)
        self.assertIsNone(inst.response_body)
        self.assertIs(inst.sslctx, sslctx)
        self.assertIs(inst.check_hostname, False)

