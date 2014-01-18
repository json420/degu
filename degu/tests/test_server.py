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

from dbase32 import random_id

from .helpers import TempDir
from degu.parser import ParseError
from degu import server


class TestFunctions(TestCase):
    def test_parse_request(self):
        # Bad separators:
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET/foo/bar?stuff=junkHTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request Line')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET  /foo/bar?stuff=junk  HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request Line')

        # Bad method:
        with self.assertRaises(ParseError) as cm:
            server.parse_request('COPY /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Method Not Allowed')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('get /foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Method Not Allowed')

        # All manner of URI problems:
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET foo/bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Start')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /../bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI DotDot')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET //bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Double Slash')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /foo\\/bar HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Backslash')

        # Same as above, but toss a query into the mix
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET foo/bar?stuff=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Start')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=.. HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI DotDot')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=// HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Double Slash')
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff\\=junk HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Naughty URI Backslash')

        # Multiple "?" present in URI:
        with self.assertRaises(ParseError) as cm:
            server.parse_request('GET /foo/bar?stuff=junk?other=them HTTP/1.1')
        self.assertEqual(cm.exception.reason, 'Bad Request URI Query')

        # Bad protocol:
        with self.assertRaises(ParseError) as cm:
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
