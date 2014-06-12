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
Unit tests for the `degu.util` module`
"""

from unittest import TestCase
from io import BytesIO
from copy import deepcopy

from .helpers import random_data, random_chunks

from degu import base, util


class TestFunctions(TestCase):
    def test_shift_path(self):
        # both script and path are empty:
        request = {'script': [], 'path': []}
        with self.assertRaises(IndexError):
            util.shift_path(request)
        self.assertEqual(request, {'script': [], 'path': []})

        # path is empty:
        request = {'script': ['foo'], 'path': []}
        with self.assertRaises(IndexError):
            util.shift_path(request)
        self.assertEqual(request, {'script': ['foo'], 'path': []})

        # start with populated path:
        request = {'script': [], 'path': ['foo', 'bar', 'baz']}
        self.assertEqual(util.shift_path(request), 'foo')
        self.assertEqual(request, {'script': ['foo'], 'path': ['bar', 'baz']})
        self.assertEqual(util.shift_path(request), 'bar')
        self.assertEqual(request, {'script': ['foo', 'bar'], 'path': ['baz']})
        self.assertEqual(util.shift_path(request), 'baz')
        self.assertEqual(request, {'script': ['foo', 'bar', 'baz'], 'path': []})
        with self.assertRaises(IndexError):
            util.shift_path(request)
        self.assertEqual(request, {'script': ['foo', 'bar', 'baz'], 'path': []})

    def test_relative_uri(self):
        # script, path, and query are all empty:
        request = {'script': [], 'path': [], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/')
        self.assertEqual(request, {'script': [], 'path': [], 'query': ''})

        # only script:
        request = {'script': ['foo'], 'path': [], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/')
        self.assertEqual(request,
            {'script': ['foo'], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', ''], 'path': [], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/')
        self.assertEqual(request,
            {'script': ['foo', ''], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', 'bar'], 'path': [], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/')
        self.assertEqual(request,
            {'script': ['foo', 'bar'], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', 'bar', ''], 'path': [], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/')
        self.assertEqual(request,
            {'script': ['foo', 'bar', ''], 'path': [], 'query': ''}
        )

        # only path:
        request = {'script': [], 'path': ['foo'], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/foo')
        self.assertEqual(request,
            {'script': [], 'path': ['foo'], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', ''], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/foo/')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', ''], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', 'bar'], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/foo/bar')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', 'bar'], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', 'bar', ''], 'query': ''}
        self.assertEqual(util.relative_uri(request), '/foo/bar/')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', 'bar', ''], 'query': ''}
        )

        # only query:
        request = {'script': [], 'path': [], 'query': 'hello'}
        self.assertEqual(util.relative_uri(request), '/?hello')
        self.assertEqual(request,
            {'script': [], 'path': [], 'query': 'hello'}
        )
        request = {'script': [], 'path': [], 'query': 'stuff=junk'}
        self.assertEqual(util.relative_uri(request), '/?stuff=junk')
        self.assertEqual(request,
            {'script': [], 'path': [], 'query': 'stuff=junk'}
        )

        # All of the above:
        request = {'script': ['foo'], 'path': ['bar'], 'query': 'hello'}
        self.assertEqual(util.relative_uri(request), '/bar?hello')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar'], 'query': 'hello'}
        )
        request = {'script': ['foo'], 'path': ['bar', ''], 'query': 'hello'}
        self.assertEqual(util.relative_uri(request), '/bar/?hello')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar', ''], 'query': 'hello'}
        )
        request = {'script': ['foo'], 'path': ['bar'], 'query': 'one=two'}
        self.assertEqual(util.relative_uri(request), '/bar?one=two')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar'], 'query': 'one=two'}
        )
        request = {'script': ['foo'], 'path': ['bar', ''], 'query': 'one=two'}
        self.assertEqual(util.relative_uri(request), '/bar/?one=two')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar', ''], 'query': 'one=two'}
        )

    def test_absolute_uri(self):
        # script, path, and query are all empty:
        request = {'script': [], 'path': [], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/')
        self.assertEqual(request, {'script': [], 'path': [], 'query': ''})

        # only script:
        request = {'script': ['foo'], 'path': [], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo')
        self.assertEqual(request,
            {'script': ['foo'], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', ''], 'path': [], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/')
        self.assertEqual(request,
            {'script': ['foo', ''], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', 'bar'], 'path': [], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/bar')
        self.assertEqual(request,
            {'script': ['foo', 'bar'], 'path': [], 'query': ''}
        )
        request = {'script': ['foo', 'bar', ''], 'path': [], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/bar/')
        self.assertEqual(request,
            {'script': ['foo', 'bar', ''], 'path': [], 'query': ''}
        )

        # only path:
        request = {'script': [], 'path': ['foo'], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo')
        self.assertEqual(request,
            {'script': [], 'path': ['foo'], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', ''], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', ''], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', 'bar'], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/bar')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', 'bar'], 'query': ''}
        )
        request = {'script': [], 'path': ['foo', 'bar', ''], 'query': ''}
        self.assertEqual(util.absolute_uri(request), '/foo/bar/')
        self.assertEqual(request,
            {'script': [], 'path': ['foo', 'bar', ''], 'query': ''}
        )

        # only query:
        request = {'script': [], 'path': [], 'query': 'hello'}
        self.assertEqual(util.absolute_uri(request), '/?hello')
        self.assertEqual(request,
            {'script': [], 'path': [], 'query': 'hello'}
        )
        request = {'script': [], 'path': [], 'query': 'stuff=junk'}
        self.assertEqual(util.absolute_uri(request), '/?stuff=junk')
        self.assertEqual(request,
            {'script': [], 'path': [], 'query': 'stuff=junk'}
        )

        # All of the above:
        request = {'script': ['foo'], 'path': ['bar'], 'query': 'hello'}
        self.assertEqual(util.absolute_uri(request), '/foo/bar?hello')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar'], 'query': 'hello'}
        )
        request = {'script': ['foo'], 'path': ['bar', ''], 'query': 'hello'}
        self.assertEqual(util.absolute_uri(request), '/foo/bar/?hello')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar', ''], 'query': 'hello'}
        )
        request = {'script': ['foo'], 'path': ['bar'], 'query': 'one=two'}
        self.assertEqual(util.absolute_uri(request), '/foo/bar?one=two')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar'], 'query': 'one=two'}
        )
        request = {'script': ['foo'], 'path': ['bar', ''], 'query': 'one=two'}
        self.assertEqual(util.absolute_uri(request), '/foo/bar/?one=two')
        self.assertEqual(request,
            {'script': ['foo'], 'path': ['bar', ''], 'query': 'one=two'}
        )

    def test_output_from_input(self):
        orig = {
            'rgi.Output': base.Output,
            'rgi.ChunkedOutput': base.ChunkedOutput,
        }
        connection = deepcopy(orig)

        # input_body is None:
        self.assertIsNone(util.output_from_input(connection, None))
        self.assertEqual(connection, orig)

        # input_body is an Input instance:
        data = random_data()
        rfile = BytesIO(data)
        input_body = base.Input(rfile, len(data))
        output_body = util.output_from_input(connection, input_body)
        self.assertIsInstance(output_body, base.Output)
        self.assertIs(output_body.source, input_body)
        self.assertEqual(output_body.content_length, len(data))
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(input_body.closed, False)
        self.assertIs(output_body.closed, False)
        self.assertEqual(list(output_body), [data])
        self.assertIs(input_body.closed, True)
        self.assertIs(output_body.closed, True)
        self.assertEqual(rfile.tell(), len(data))
        self.assertEqual(connection, orig)

        # input_body is a ChunkedInput instance:
        chunks = random_chunks()
        rfile = BytesIO()
        total = 0
        for chunk in chunks:
            total += base.write_chunk(rfile, chunk)
        self.assertEqual(rfile.tell(), total)
        rfile.seek(0)
        input_body = base.ChunkedInput(rfile)
        output_body = util.output_from_input(connection, input_body)
        self.assertIsInstance(output_body, base.ChunkedOutput)
        self.assertIs(output_body.source, input_body)
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(input_body.closed, False)
        self.assertIs(output_body.closed, False)
        self.assertEqual(list(output_body), chunks)
        self.assertIs(input_body.closed, True)
        self.assertIs(output_body.closed, True)
        self.assertEqual(rfile.tell(), total)
        self.assertEqual(connection, orig)

