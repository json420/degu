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
Unit tests for the `degu.rgi` module`
"""

from unittest import TestCase
import io
from copy import deepcopy

from degu import base
from degu import rgi


class TestFunctions(TestCase):
    def test_validate_session(self):
        # session isn't a `dict`:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(['hello'])
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('session', dict, list, ['hello'])
        )

        # session has non-str keys:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session({'foo': 'bar', b'hello': 'world'})
        self.assertEqual(str(cm.exception),
            "session: keys must be <class 'str'>; got a <class 'bytes'>: b'hello'"
        )

        # Missing required keys:
        good = {
            'rgi.version': (0, 1),
            'rgi.Body': base.Body,
            'rgi.BodyIter': base.BodyIter,
            'rgi.ChunkedBody': base.ChunkedBody,
            'rgi.ChunkedBodyIter': base.ChunkedBodyIter,
            'scheme': 'http',
            'protocol': 'HTTP/1.1',
            'server': ('127.0.0.1', 60111),
            'client': ('127.0.0.1', 52521),
            'requests': 0,
        }
        self.assertIsNone(rgi._validate_session(good))
        for key in sorted(good):
            bad = deepcopy(good)
            del bad[key]
            with self.assertRaises(ValueError) as cm:
                rgi._validate_session(bad)
            self.assertEqual(str(cm.exception),
                'session[{!r}] does not exist'.format(key)
            )

        # session['rgi.version'] isn't a tuple:
        bad = deepcopy(good)
        bad['rgi.version'] = '0.1'
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['rgi.version']: need a <class 'tuple'>; got a <class 'str'>: '0.1'"
        )

        # session['rgi.version'] tuple doesn't have exactly 2 items:
        bad = deepcopy(good)
        bad['rgi.version'] = tuple()
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "len(session['rgi.version']) must be 2; got 0: ()"
        )
        bad['rgi.version'] = (0,)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "len(session['rgi.version']) must be 2; got 1: (0,)"
        )
        bad['rgi.version'] = (0, 1, 2)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "len(session['rgi.version']) must be 2; got 3: (0, 1, 2)"
        )

        # session['rgi.version'][0] isn't an `int`:
        bad = deepcopy(good)
        bad['rgi.version'] = ('0', 1)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['rgi.version'][0]: need a <class 'int'>; got a <class 'str'>: '0'"
        )

        # session['rgi.version'][1] isn't an `int`:
        bad = deepcopy(good)
        bad['rgi.version'] = (0, 1.0)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['rgi.version'][1]: need a <class 'int'>; got a <class 'float'>: 1.0"
        )

        # session['rgi.version'][0] is negative:
        bad = deepcopy(good)
        bad['rgi.version'] = (-1, 0)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['rgi.version'][0] must be >= 0; got -1"
        )

        # session['rgi.version'][1] is negative:
        bad = deepcopy(good)
        bad['rgi.version'] = (0, -1)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['rgi.version'][1] must be >= 0; got -1"
        )

        # session['rgi.Body'] isn't an object subclass:
        bad = deepcopy(good)
        value = base.Body(io.BytesIO(), 17)
        bad['rgi.Body'] = value
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.ChunkedBody'] isn't an object subclass:
        bad = deepcopy(good)
        value = base.ChunkedBody(io.BytesIO())
        bad['rgi.ChunkedBody'] = value
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.BodyIter'] isn't an object subclass:
        bad = deepcopy(good)
        value = base.BodyIter([], 17)
        bad['rgi.BodyIter'] = value
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.ChunkedBodyIter'] isn't an object subclass:
        bad = deepcopy(good)
        value = base.ChunkedBodyIter([])
        bad['rgi.ChunkedBodyIter'] = value
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # Bad session['scheme'] value:
        bad = deepcopy(good)
        bad['scheme'] = 'ftp'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['scheme']: value 'ftp' not in ('http', 'https')"
        )

        # Bad session['protocol'] value:
        bad = deepcopy(good)
        bad['protocol'] = 'HTTP/1.0'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['protocol']: value 'HTTP/1.0' not in ('HTTP/1.1',)"
        )

        # session['requests'] isn't an `int`:
        bad = deepcopy(good)
        bad['requests'] = 0.0
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['requests']: need a <class 'int'>; got a <class 'float'>: 0.0"
        )

        # session['requests'] is negative:
        bad = deepcopy(good)
        bad['requests'] = -1
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['requests'] must be >= 0; got -1"
        )

    def test_validate_request(self):
        # request isn't a `dict`:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(['hello'])
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('request', dict, list, ['hello'])
        )

        # request has non-str keys:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request({'foo': 'bar', b'hello': 'world'})
        self.assertEqual(str(cm.exception),
            "request: keys must be <class 'str'>; got a <class 'bytes'>: b'hello'"
        )

        good = {
            'method': 'GET',
            'script': ['foo'],
            'path': ['bar'],
            'query': 'stuff=junk',
            'headers': {},
            'body': None,
        }
        self.assertIsNone(rgi._validate_request(good))
        for key in sorted(good):
            bad = deepcopy(good)
            del bad[key]
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(bad)
            self.assertEqual(str(cm.exception),
                'request[{!r}] does not exist'.format(key)
            )

        # Bad request['method'] value:
        bad = deepcopy(good)
        bad['method'] = 'OPTIONS'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(bad)
        self.assertEqual(str(cm.exception),
            "request['method']: value 'OPTIONS' not in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD')"
        )
