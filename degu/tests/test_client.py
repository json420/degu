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
from urllib.parse import urlparse

from .helpers import TempDir, DummySocket, DummyFile
from degu.base import TYPE_ERROR
from degu.sslhelpers import random_id
from degu.misc import TempPKI
from degu import base, client


# Some bad address permutations:
BAD_ADDRESSES = (
    ('::1',),
    ('127.0.0.1',),
    ('::1', 5678, 0),
    ('127.0.0.1', 5678, 0),
    ('::1', 5678, 0, 0, 0),
    ('127.0.0.1', 5678, 0, 0, 0),
)

# Some good address permutations:
GOOD_ADDRESSES = (
    ('127.0.0.1', 5678),
    ('example.com', 80),
    ('example.com', 443),
    ('::1', 5678, 0, 0),
    ('fe80::290:f5ff:fef0:d35c', 5678, 0, 2),
)

# Expected host for each of the above good addresses:
HOSTS = (
    '127.0.0.1:5678',
    'example.com:80',
    'example.com:443',
    '[::1]:5678',
    '[fe80::290:f5ff:fef0:d35c]:5678',
)


class TestNamedTuples(TestCase):
    def test_Response(self):
        tup = client.Response('da status', 'da reason', 'da headers', 'da body')
        self.assertIsInstance(tup, tuple)
        self.assertEqual(tup.status, 'da status')
        self.assertEqual(tup.reason, 'da reason')
        self.assertEqual(tup.headers, 'da headers')
        self.assertEqual(tup.body, 'da body')


class TestFunctions(TestCase):
    def test_build_client_sslctx(self):
        # Empty config, will verify against system-wide CAs, and check_hostname
        # should default to True:
        sslctx = client.build_client_sslctx({})
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, True)

        # We don't not allow check_hostname to be False when verifying against
        # the system-wide CAs:
        with self.assertRaises(ValueError) as cm:
            client.build_client_sslctx({'check_hostname': False})
        self.assertEqual(str(cm.exception),
            'check_hostname must be True when using default verify paths'
        )

        # Should work fine when explicitly providing {'check_hostname': True}:
        sslctx = client.build_client_sslctx({'check_hostname': True})
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, True)

        # Authenticated client config:
        pki = TempPKI()
        config = pki.get_client_config()
        self.assertEqual(set(config),
            {'ca_file', 'cert_file', 'key_file', 'check_hostname'}
        )
        self.assertIs(config['check_hostname'], False)
        sslctx = client.build_client_sslctx(config)
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, False)

        # check_hostname should default to True:
        del config['check_hostname']
        sslctx = client.build_client_sslctx(config)
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, True)

        # Anonymous client config:
        config = pki.get_anonymous_client_config()
        self.assertEqual(set(config), {'ca_file', 'check_hostname'})
        self.assertIs(config['check_hostname'], False)
        sslctx = client.build_client_sslctx(config)
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, False)

        # check_hostname should default to True:
        del config['check_hostname']
        sslctx = client.build_client_sslctx(config)
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
        self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(sslctx.check_hostname, True)

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
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 200OK')
        self.assertEqual(str(cm.exception), 'need more than 2 values to unpack')

        # Bad protocol:
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.0 200 OK')
        self.assertEqual(str(cm.exception), "bad HTTP protocol: 'HTTP/1.0'")

        # Status not an int:
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 17.9 OK')
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 10: '17.9'"
        )

        # Status outside valid range:
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 99 OK')
        self.assertEqual(str(cm.exception), 'need 100 <= status <= 599; got 99')
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 600 OK')
        self.assertEqual(str(cm.exception), 'need 100 <= status <= 599; got 600')
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 -200 OK')
        self.assertEqual(str(cm.exception), 'need 100 <= status <= 599; got -200')

        # Empty reason:
        with self.assertRaises(ValueError) as cm:
            client.parse_status('HTTP/1.1 200 ')
        self.assertEqual(str(cm.exception), 'empty reason')

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

    def test_create_client(self):
        # IPv6, with port:
        url = 'http://[fe80::e8b:fdff:fe75:402c]:54321/'
        inst = client.create_client(url)
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 54321))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]:54321'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 54321))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]:54321'})

        # IPv6, no port (should default to 80):
        url = 'http://[fe80::e8b:fdff:fe75:402c]/'
        inst = client.create_client(url)
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 80))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 80))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]'})

        # IPv4, with port:
        url = 'http://10.17.76.69:54321/'
        inst = client.create_client(url)
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('10.17.76.69', 54321))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69:54321'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('10.17.76.69', 54321))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69:54321'})

        # IPv4, no port (should default to 80):
        url = 'http://10.17.76.69/'
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('10.17.76.69', 80))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('10.17.76.69', 80))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69'})

        # Name, with port:
        url = 'http://www.example.com:54321/'
        inst = client.create_client(url)
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('www.example.com', 54321))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com:54321'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('www.example.com', 54321))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com:54321'})

        # Name, no port (should default to 80):
        url = 'http://www.example.com/'
        inst = client.create_client(url)
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('www.example.com', 80))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com'})
        inst = client.create_client(urlparse(url))
        self.assertIsInstance(inst, client.Client)
        self.assertEqual(inst.address, ('www.example.com', 80))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com'})

        # Bad scheme:
        url = 'https://www.example.com/'
        with self.assertRaises(ValueError) as cm:
            client.create_client(url)
        self.assertEqual(str(cm.exception), "scheme must be 'http', got 'https'")
        with self.assertRaises(ValueError) as cm:
            client.create_client(urlparse(url))
        self.assertEqual(str(cm.exception), "scheme must be 'http', got 'https'")

    def test_create_sslclient(self):
        pki = TempPKI()
        sslctx = client.build_client_sslctx(pki.get_client_config())

        # IPv6, with port:
        url = 'https://[fe80::e8b:fdff:fe75:402c]:54321/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 54321))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]:54321'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 54321))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]:54321'})

        # IPv6, no port (should default to 443):
        url = 'https://[fe80::e8b:fdff:fe75:402c]/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 443))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('fe80::e8b:fdff:fe75:402c', 443))
        self.assertEqual(inst.base_headers, {'host': '[fe80::e8b:fdff:fe75:402c]'})

        # IPv4, with port:
        url = 'https://10.17.76.69:54321/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('10.17.76.69', 54321))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69:54321'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('10.17.76.69', 54321))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69:54321'})

        # IPv4, no port (should default to 443):
        url = 'https://10.17.76.69/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('10.17.76.69', 443))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('10.17.76.69', 443))
        self.assertEqual(inst.base_headers, {'host': '10.17.76.69'})

        # Name, with port:
        url = 'https://www.example.com:54321/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('www.example.com', 54321))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com:54321'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('www.example.com', 54321))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com:54321'})

        # Name, no port (should default to 443):
        url = 'https://www.example.com/'
        inst = client.create_sslclient(sslctx, url)
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('www.example.com', 443))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com'})
        inst = client.create_sslclient(sslctx, urlparse(url))
        self.assertIsInstance(inst, client.SSLClient)
        self.assertIs(inst.sslctx, sslctx)
        self.assertEqual(inst.address, ('www.example.com', 443))
        self.assertEqual(inst.base_headers, {'host': 'www.example.com'})

        # Bad scheme:
        url = 'http://www.example.com/'
        with self.assertRaises(ValueError) as cm:
            client.create_sslclient(sslctx, url)
        self.assertEqual(str(cm.exception), "scheme must be 'https', got 'http'")
        with self.assertRaises(ValueError) as cm:
            client.create_sslclient(sslctx, urlparse(url))
        self.assertEqual(str(cm.exception), "scheme must be 'https', got 'http'")


class TestConnection(TestCase):
    def test_init(self):
        sock = DummySocket()
        key = random_id().lower()
        value = random_id()
        base_headers = {key: value}
        inst = client.Connection(sock, base_headers)
        self.assertIsInstance(inst, client.Connection)
        self.assertIs(inst.sock, sock)
        self.assertIs(inst.base_headers, base_headers)
        self.assertEqual(inst.base_headers, {key: value})
        self.assertIs(inst.rfile, sock._rfile)
        self.assertIs(inst.wfile, sock._wfile)
        self.assertIsNone(inst.response_body)
        self.assertIs(inst.closed, False)
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

    def test_del(self):
        class ConnectionSubclass(client.Connection):
            def __init__(self):
                self._calls = 0

            def close(self):
                self._calls += 1

        inst = ConnectionSubclass()
        self.assertEqual(inst._calls, 0)
        self.assertIsNone(inst.__del__())
        self.assertEqual(inst._calls, 1)
        self.assertIsNone(inst.__del__())
        self.assertEqual(inst._calls, 2)

    def test_close(self):
        sock = DummySocket()
        inst = client.Connection(sock, None)
        sock._calls.clear()

        # When Connection.closed is False:
        self.assertIsNone(inst.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])
        self.assertIs(inst.closed, True)

        # Now when Connection.closed is True:
        self.assertIsNone(inst.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])
        self.assertIs(inst.closed, True)


class TestClient(TestCase):
    def test_init(self):
        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            client.Client(1234)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        for address in BAD_ADDRESSES:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                client.Client(address)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # Non-absolute/non-normalized AF_UNIX filename:
        with self.assertRaises(ValueError) as cm:
            client.Client('foo')
        self.assertEqual(str(cm.exception),
            "address: bad socket filename: 'foo'"
        )

        # `str` (AF_UNIX)
        tmp = TempDir()
        filename = tmp.join('my.socket')
        inst = client.Client(filename)
        self.assertIs(inst.address, filename)
        self.assertIs(inst.family, socket.AF_UNIX)
        self.assertEqual(inst.base_headers, {})

        # `bytes` (AF_UNIX):
        address = b'\x0000022'
        inst = client.Client(address)
        self.assertIs(inst.address, address)
        self.assertIs(inst.family, socket.AF_UNIX)
        self.assertEqual(inst.base_headers, {})

        # A number of good address permutations:
        for (address, host) in zip(GOOD_ADDRESSES, HOSTS):
            inst = client.Client(address)
            self.assertIsInstance(inst, client.Client)
            self.assertIs(inst.address, address)
            self.assertIsNone(inst.conn)
            self.assertIsNone(inst.response_body)
            self.assertEqual(inst.base_headers, {})

    def test_repr(self):
        class Custom(client.Client):
            pass

        for address in GOOD_ADDRESSES:
            inst = client.Client(address)
            self.assertEqual(repr(inst), 'Client({!r})'.format(address))
            inst = Custom(address)
            self.assertEqual(repr(inst), 'Custom({!r})'.format(address))

    def test_connect(self):
        class ClientSubclass(client.Client):
            def __init__(self, sock):
                self._sock = sock

            def create_socket(self):
                return self._sock

        sock = DummySocket()
        inst = ClientSubclass(sock)
        conn = inst.connect()
        self.assertIsInstance(conn, client.Connection)
        self.assertIs(conn.sock, sock)
        self.assertIs(conn.rfile, sock._rfile)
        self.assertIs(conn.wfile, sock._wfile)
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

        # Should return a new Connection instance each time:
        conn2 = inst.connect()
        self.assertIsNot(conn2, conn)
        self.assertIsInstance(conn2, client.Connection)
        self.assertIs(conn2.sock, sock)
        self.assertIs(conn2.rfile, sock._rfile)
        self.assertIs(conn2.wfile, sock._wfile)
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

    def test_request(self):
        # Test when the previous response body wasn't consumed:
        class DummyBody:
            closed = False

        inst = client.Client(('::1', 5678))
        inst.response_body = DummyBody
        with self.assertRaises(client.UnconsumedResponseError) as cm:
            inst.request(None, None)
        self.assertIs(cm.exception.body, DummyBody)
        self.assertEqual(str(cm.exception),
            'previous response body not consumed: {!r}'.format(DummyBody)
        )


class TestSSLClient(TestCase):
    def test_init(self):
        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            client.SSLClient('foo', None)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, None)
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
            client.SSLClient(sslctx, None)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # verify_mode is not ssl.CERT_REQUIRED:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, None)
        self.assertEqual(str(cm.exception),
            'sslctx.verify_mode must be ssl.CERT_REQUIRED'
        )

        # Good sslctx from here on:
        sslctx.verify_mode = ssl.CERT_REQUIRED

        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            client.SSLClient(sslctx, 1234)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        for address in BAD_ADDRESSES:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                client.SSLClient(sslctx, address)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # A number of good address permutations:
        for (address, host) in zip(GOOD_ADDRESSES, HOSTS):
            inst = client.SSLClient(sslctx, address)
            self.assertIs(inst.address, address)
            self.assertIsNone(inst.conn)
            self.assertIsNone(inst.response_body)
            self.assertEqual(inst.base_headers, {})

    def test_repr(self):
        class Custom(client.SSLClient):
            pass

        pki = TempPKI()
        sslctx = client.build_client_sslctx(pki.get_client_config())

        for address in GOOD_ADDRESSES:
            inst = client.SSLClient(sslctx, address)
            self.assertEqual(repr(inst),
                'SSLClient({!r}, {!r})'.format(sslctx, address)
            )
            inst = Custom(sslctx, address)
            self.assertEqual(repr(inst),
                'Custom({!r}, {!r})'.format(sslctx, address)
            )
