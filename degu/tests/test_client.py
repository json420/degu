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

from .helpers import TempDir
from degu import base, client


class TestFunctions(TestCase):
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

