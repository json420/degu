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
import os
import string
from random import SystemRandom
from copy import deepcopy

from degu import rgi


random = SystemRandom()


def random_identifier():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(17))


def random_value():
    return os.urandom(10)


class MockBody:
    def __init__(self, **kw):
        for (key, value) in kw.items():
            assert not key.startswith('_')
            setattr(self, key, value)


class Body(MockBody):
    """
    Mock class used for session['rgi.Body'].
    """


class BodyIter(MockBody):
    """
    Mock class used for session['rgi.BodyIter'].
    """


class ChunkedBody(MockBody):
    """
    Mock class used for session['rgi.ChunkedBody'].
    """


class ChunkedBodyIter(MockBody):
    """
    Mock class used for session['rgi.ChunkedBodyIter'].
    """


class TestMockBody(TestCase):
    def test_init(self):
        for klass in (Body, BodyIter, ChunkedBody, ChunkedBodyIter):
            # No kw args:
            body = klass()
            self.assertIsInstance(body, MockBody)
            self.assertEqual(
                list(filter(lambda n: not n.startswith('_'), dir(body))),
                []
            )

            # One kw arg:
            key1 = random_identifier()
            val1 = os.urandom(16)
            kw = {key1: val1}
            body = klass(**kw)
            self.assertIsInstance(body, MockBody)
            self.assertEqual(
                list(filter(lambda n: not n.startswith('_'), dir(body))),
                [key1]
            )
            self.assertIs(getattr(body, key1), val1)

            # Two kw args:
            key2 = random_identifier()
            val2 = os.urandom(16)
            kw = {key1: val1, key2: val2}
            body = klass(**kw)
            self.assertIsInstance(body, MockBody)
            self.assertEqual(
                list(filter(lambda n: not n.startswith('_'), dir(body))),
                sorted([key1, key2])
            )
            self.assertIs(getattr(body, key1), val1)
            self.assertIs(getattr(body, key2), val2)

            # Three kw args:
            key3 = random_identifier()
            val3 = os.urandom(16)
            kw = {key1: val1, key2: val2, key3: val3}
            body = klass(**kw)
            self.assertIsInstance(body, MockBody)
            self.assertEqual(
                list(filter(lambda n: not n.startswith('_'), dir(body))),
                sorted([key1, key2, key3])
            )
            self.assertIs(getattr(body, key1), val1)
            self.assertIs(getattr(body, key2), val2)
            self.assertIs(getattr(body, key3), val3)


class TestFunctions(TestCase):
    def test_getattr(self):
        class Example:
            def __init__(self, marker):
                self.foo = marker

        label = "request['body']"
        marker = os.urandom(16)
        obj = Example(marker)
        self.assertIs(rgi._getattr(label, obj, 'foo'), marker)
        with self.assertRaises(ValueError) as cm:
            rgi._getattr(label, obj, 'bar')
        self.assertEqual(str(cm.exception),
            "request['body']: 'Example' object has no attribute 'bar'"
        )

    def test_ensure_attr_is(self):
        class Example:
            def __init__(self, key, value):
                setattr(self, key, value)

        label = random_identifier()
        key = random_identifier()
        value = random_value()
        obj = Example(key, value)

        # Attribute is expected:
        self.assertIsNone(rgi._ensure_attr_is(label, obj, key, value))

        # Attribute is not expected:
        value2 = random_value()
        with self.assertRaises(ValueError) as cm:
            rgi._ensure_attr_is(label, obj, key, value2)
        self.assertEqual(str(cm.exception),
            "{}.{} must be {!r}; got {!r}".format(label, key, value2, value)
        )

        # Attribute is missing:
        key2 = random_identifier()
        with self.assertRaises(ValueError) as cm:
            rgi._ensure_attr_is(label, obj, key2, value)
        self.assertEqual(str(cm.exception),
            "{}: 'Example' object has no attribute {!r}".format(label, key2)
        )

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
            'rgi.Body': Body,
            'rgi.BodyIter': BodyIter,
            'rgi.ChunkedBody': ChunkedBody,
            'rgi.ChunkedBodyIter': ChunkedBodyIter,
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

        # session['rgi.Body'] is an instance instead of a subclass:
        bad = deepcopy(good)
        bad['rgi.Body'] = Body()
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.ChunkedBody'] is an instance instead of a subclass:
        bad = deepcopy(good)
        bad['rgi.ChunkedBody'] = ChunkedBody()
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.BodyIter'] is an instance instead of a subclass:
        bad = deepcopy(good)
        bad['rgi.BodyIter'] = BodyIter()
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),'issubclass() arg 1 must be a class')

        # session['rgi.ChunkedBodyIter'] is an instance instead of a subclass:
        bad = deepcopy(good)
        value = ChunkedBodyIter()
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
        # Validator.__call__() will extract these from session:
        body_types = (Body, ChunkedBody)

        # request isn't a `dict`:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(['hello'], body_types)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('request', dict, list, ['hello'])
        )

        # request has non-str keys:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request({'foo': 'bar', b'hello': 'world'}, body_types)
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
        self.assertIsNone(rgi._validate_request(good, body_types))
        for key in sorted(good):
            bad = deepcopy(good)
            del bad[key]
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(bad, body_types)
            self.assertEqual(str(cm.exception),
                'request[{!r}] does not exist'.format(key)
            )

        # Bad request['method'] value:
        bad = deepcopy(good)
        bad['method'] = 'OPTIONS'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['method']: value 'OPTIONS' not in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD')"
        )

        # Bad request['script'] type:
        bad = deepcopy(good)
        bad['script'] = ('foo',)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['script']: need a <class 'list'>; got a <class 'tuple'>: ('foo',)"
        )

        # Bad request['script'][0] type:
        bad = deepcopy(good)
        bad['script'] = [b'foo']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['script'][0]: need a <class 'str'>; got a <class 'bytes'>: b'foo'"
        )

        # Bad request['script'][1] type:
        bad = deepcopy(good)
        bad['script'] = ['foo', b'baz']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['script'][1]: need a <class 'str'>; got a <class 'bytes'>: b'baz'"
        )

        # Bad request['path'] type:
        bad = deepcopy(good)
        bad['path'] = ('bar',)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['path']: need a <class 'list'>; got a <class 'tuple'>: ('bar',)"
        )

        # Bad request['path'][0] type:
        bad = deepcopy(good)
        bad['path'] = [b'bar']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['path'][0]: need a <class 'str'>; got a <class 'bytes'>: b'bar'"
        )

        # Bad request['path'][1] type:
        bad = deepcopy(good)
        bad['path'] = ['bar', b'baz']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['path'][1]: need a <class 'str'>; got a <class 'bytes'>: b'baz'"
        )

        # Bad request['query'] type:
        bad = deepcopy(good)
        bad['query'] = {'stuff': 'junk'}
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['query']: need a <class 'str'>; got a <class 'dict'>: {'stuff': 'junk'}"
        )

        # Bad request['headers'] type:
        bad = deepcopy(good)
        bad['headers'] = [('content-length', 17)]
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(bad, body_types)
        self.assertEqual(str(cm.exception),
            "request['headers']: need a <class 'dict'>; got a <class 'list'>: [('content-length', 17)]"
        )

        # Bad request['body'] type:
        bad_bodies = (BodyIter(), ChunkedBodyIter())
        for body in bad_bodies:
            bad = deepcopy(good)
            bad['body'] = body
            with self.assertRaises(TypeError) as cm:
                rgi._validate_request(bad, body_types)
            self.assertEqual(str(cm.exception),
                rgi.TYPE_ERROR.format(
                    "request['body']", body_types, type(body), body
                )
            )

        # Body is missing 'closed' attribute
        for klass in (Body, ChunkedBody):
            bad = deepcopy(good)
            bad['body'] = klass()
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(bad, body_types)
            self.assertEqual(str(cm.exception),
                "request['body']: {!r} object has no attribute 'closed'".format(klass.__name__)
            )

        # body.closed must be False prior to calling the application:
        for klass in (Body, ChunkedBody):
            bad = deepcopy(good)
            bad['body'] = klass(closed=True)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(bad, body_types)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(bad, body_types)
            self.assertEqual(str(cm.exception),
                "request['body'].closed must be False; got True"
            )

        # Test the two allowed body types (non-None):
        bodies = [
            Body(closed=False),
            ChunkedBody(closed=False),
        ]
        for body in bodies:
            request = deepcopy(good)
            request['body'] = body
            self.assertIsNone(rgi._validate_request(request, body_types))

  
