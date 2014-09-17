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
from collections import namedtuple

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
    Mock class used for bodies.Body.
    """


class BodyIter(MockBody):
    """
    Mock class used for bodies.BodyIter.
    """


class ChunkedBody(MockBody):
    """
    Mock class used for bodies.ChunkedBody.
    """


class ChunkedBodyIter(MockBody):
    """
    Mock class used for bodies.ChunkedBodyIter.
    """


Bodies = namedtuple('Bodies', 'Body BodyIter ChunkedBody ChunkedBodyIter')
default_bodies = Bodies(Body, BodyIter, ChunkedBody, ChunkedBodyIter)


def build_session(**kw):
    session = {
        'scheme': 'http',
        'client': ('127.0.0.1', 52521),
        'requests': 0,
    }
    for (key, value) in kw.items():
        session[key] = value
    return session


def build_request(**kw):
    request = {
        'method': 'POST',
        'script': ['foo'],
        'path': ['bar'],
        'query': 'stuff=junk',
        'headers': {},
        'body': None,
    }
    for (key, value) in kw.items():
        request[key] = value
    return request


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
            val1 = random_value()
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
            val2 = random_value()
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
            val3 = random_value()
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
            def __init__(self, key, value):
                setattr(self, key, value)

        label = random_identifier()
        key = random_identifier()
        value = random_value()
        obj = Example(key, value)

        # Attribute is present:
        (L, V) = rgi._getattr(label, obj, key)
        self.assertEqual(L, '{}.{}'.format(label, key))
        self.assertIs(V, value)

        # Attribute is missing:
        key2 = random_identifier()
        with self.assertRaises(ValueError) as cm:
            rgi._getattr(label, obj, key2)
        self.assertEqual(str(cm.exception),
            "{}: 'Example' object has no attribute {!r}".format(label, key2)
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

    def test_check_dict(self):
        # obj is not a dict:
        label = random_identifier()
        obj = random_identifier()
        with self.assertRaises(TypeError) as cm:
            rgi._check_dict(label, obj)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format(label, dict, str, obj)
        )

        # obj contains a non-string key:
        obj = dict(
            (random_identifier(), random_value()) for i in range(5)
        )
        key = random_identifier().encode()
        obj[key] = random_value()
        with self.assertRaises(TypeError) as cm:
            rgi._check_dict(label, obj)
        self.assertEqual(str(cm.exception),
            '{}: keys must be {!r}; got a {!r}: {!r}'.format(label, str, bytes, key)
        )

        # All good:
        obj = dict(
            (random_identifier(), random_value()) for i in range(6)
        )
        self.assertIsNone(rgi._check_dict(label, obj))

    def test_check_headers(self):
        # headers is not a dict:
        label = random_identifier()
        headers = random_identifier()
        with self.assertRaises(TypeError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format(label, dict, str, headers)
        )

        # headers contains a non-string key:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        key = random_identifier().encode()
        headers[key] = random_identifier()
        with self.assertRaises(TypeError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            '{}: keys must be {!r}; got a {!r}: {!r}'.format(label, str, bytes, key)
        )

        # headers contains a non-casefolded key:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        key = random_identifier().upper()
        headers[key] = random_identifier()
        with self.assertRaises(ValueError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            '{}: non-casefolded header name: {!r}'.format(label, key)
        )

        # headers contains a non-string value:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        key = random_identifier()
        value = random_value()
        headers[key] = value
        with self.assertRaises(TypeError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            '{}[{!r}]: need a {!r}; got a {!r}: {!r}'.format(label, key, str, bytes, value)
        )

        # content-length plus tranfer-encoding
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['content-length'] = random_identifier()
        headers['transfer-encoding'] = random_identifier()
        with self.assertRaises(ValueError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            '{}: content-length and transfer-encoding in headers'.format(label)
        )

        # content-length isn't an int:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['content-length'] = '17'
        with self.assertRaises(TypeError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            "{}['content-length']: need a {!r}; got a {!r}: '17'".format(label, int, str)
        )

        # content-length is negative:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['content-length'] = -1
        with self.assertRaises(ValueError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            "{}['content-length']: must be >=0; got -1".format(label)
        )

        # Bad transfer-encoding:
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['transfer-encoding'] = 'clumped'
        with self.assertRaises(ValueError) as cm:
            rgi._check_headers(label, headers)
        self.assertEqual(str(cm.exception),
            "{}['transfer-encoding']: must be 'chunked'; got 'clumped'".format(label)
        )

        # All good:
        label = random_identifier()
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(6)
        )
        self.assertIsNone(rgi._check_headers(label, headers))

        # All good, with a content-length:
        label = random_identifier()
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['content-length'] = 0
        self.assertIsNone(rgi._check_headers(label, headers))

        # All good, with a transfer-encoding:
        label = random_identifier()
        headers = dict(
            (random_identifier(), random_identifier()) for i in range(5)
        )
        headers['transfer-encoding'] = 'chunked'
        self.assertIsNone(rgi._check_headers(label, headers))

    def test_check_address(self):
        # Bad address type:
        label = random_identifier()
        address = ['127.0.0.1', 12345]
        with self.assertRaises(TypeError) as cm:
            rgi._check_address(label, address)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format(label, (tuple, str, bytes), list, address)
        )
        label = random_identifier()
        address = ['::1', 12345, 0, 0]
        with self.assertRaises(TypeError) as cm:
            rgi._check_address(label, address)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format(label, (tuple, str, bytes), list, address)
        )

        # Tuple of wrong length:
        label = random_identifier()
        address = ('::1', 12345, 0)
        with self.assertRaises(ValueError) as cm:
            rgi._check_address(label, address)
        self.assertEqual(str(cm.exception),
            '{}: tuple must have 2 or 4 items; got {!r}'.format(label, address)
        )
        label = random_identifier()
        address = ('::1', 12345, 0, 0, 0)
        with self.assertRaises(ValueError) as cm:
            rgi._check_address(label, address)
        self.assertEqual(str(cm.exception),
            '{}: tuple must have 2 or 4 items; got {!r}'.format(label, address)
        )

        # Test all 4 types of good values:
        good = (
            ('127.0.0.1', 12345),
            ('::1', 23456, 0, 0),
            '/tmp/random/my.socket',
            b'\x0000022',
        )
        for address in good:    
            label = random_identifier()
            self.assertIsNone(rgi._check_address(label, address))

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
            'scheme': 'http',
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

        # Bad session['scheme'] value:
        bad = deepcopy(good)
        bad['scheme'] = 'ftp'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['scheme']: value 'ftp' not in ('http', 'https')"
        )

        # Bad session['client'] type:
        address = ['127.0.0.1', 12345]
        bad = deepcopy(good)
        bad['client'] = address
        with self.assertRaises(TypeError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format("session['client']", (tuple, str, bytes), list, address)
        )

        # session['client'] tuple is wrong length:
        address = ('::1', 2345, 0, 0, 0)
        bad = deepcopy(good)
        bad['client'] = address
        with self.assertRaises(ValueError) as cm:
            rgi._validate_session(bad)
        self.assertEqual(str(cm.exception),
            "session['client']: tuple must have 2 or 4 items; got ('::1', 2345, 0, 0, 0)"
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
        # Validator.__call__() will pass in the *bodies* argument, by which the
        # the Body and ChunkedBody classes are exposed in a server-agnostic
        # fashion.

        # request isn't a `dict`:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, ['hello'])
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('request', dict, list, ['hello'])
        )

        # request has non-str keys:
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies,
                {'foo': 'bar', b'hello': 'world'}
            )
        self.assertEqual(str(cm.exception),
            "request: keys must be <class 'str'>; got a <class 'bytes'>: b'hello'"
        )

        good = {
            'method': 'POST',
            'script': ['foo'],
            'path': ['bar'],
            'query': 'stuff=junk',
            'headers': {},
            'body': None,
        }
        self.assertIsNone(rgi._validate_request(default_bodies, good))
        for key in sorted(good):
            bad = deepcopy(good)
            del bad[key]
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(default_bodies, bad)
            self.assertEqual(str(cm.exception),
                'request[{!r}] does not exist'.format(key)
            )

        # Bad request['method'] value:
        bad = deepcopy(good)
        bad['method'] = 'OPTIONS'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['method']: value 'OPTIONS' not in ('GET', 'PUT', 'POST', 'DELETE', 'HEAD')"
        )

        # Bad request['script'] type:
        bad = deepcopy(good)
        bad['script'] = ('foo',)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['script']: need a <class 'list'>; got a <class 'tuple'>: ('foo',)"
        )

        # Bad request['script'][0] type:
        bad = deepcopy(good)
        bad['script'] = [b'foo']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['script'][0]: need a <class 'str'>; got a <class 'bytes'>: b'foo'"
        )

        # Bad request['script'][1] type:
        bad = deepcopy(good)
        bad['script'] = ['foo', b'baz']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['script'][1]: need a <class 'str'>; got a <class 'bytes'>: b'baz'"
        )

        # Bad request['path'] type:
        bad = deepcopy(good)
        bad['path'] = ('bar',)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['path']: need a <class 'list'>; got a <class 'tuple'>: ('bar',)"
        )

        # Bad request['path'][0] type:
        bad = deepcopy(good)
        bad['path'] = [b'bar']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['path'][0]: need a <class 'str'>; got a <class 'bytes'>: b'bar'"
        )

        # Bad request['path'][1] type:
        bad = deepcopy(good)
        bad['path'] = ['bar', b'baz']
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['path'][1]: need a <class 'str'>; got a <class 'bytes'>: b'baz'"
        )

        # Bad request['query'] type:
        bad = deepcopy(good)
        bad['query'] = {'stuff': 'junk'}
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['query']: need a <class 'str'>; got a <class 'dict'>: {'stuff': 'junk'}"
        )

        # Bad request['headers'] type:
        bad = deepcopy(good)
        bad['headers'] = [('content-length', 17)]
        with self.assertRaises(TypeError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['headers']: need a <class 'dict'>; got a <class 'list'>: [('content-length', 17)]"
        )

        # Bad request['body'] type:
        bad_bodies = (BodyIter(), ChunkedBodyIter())
        body_types = (Body, ChunkedBody)
        for body in bad_bodies:
            bad = deepcopy(good)
            bad['body'] = body
            with self.assertRaises(TypeError) as cm:
                rgi._validate_request(default_bodies, bad)
            self.assertEqual(str(cm.exception),
                rgi.TYPE_ERROR.format(
                    "request['body']", body_types, type(body), body
                )
            )

        ############################
        # request['body'] is `None`:

        # 'content-length' header is present:
        bad = deepcopy(good)
        bad['headers']['content-length'] = 17
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'] is None but 'content-length' header is included"
        )

        # 'transfer-encoding' header is present:
        bad = deepcopy(good)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'] is None but 'transfer-encoding' header is included"
        )

        # All valid request['method'] should work when request['body'] is None:
        for method in rgi.REQUEST_METHODS:
            request = deepcopy(good)
            request['method'] = method
            self.assertIsNone(rgi._validate_request(default_bodies, request))

        #######################################
        # request['body'] is a `Body` instance:

        # Body is missing 'chunked' attribute:
        bad = deepcopy(good)
        bad['body'] = Body(content_length=17, closed=False)
        bad['headers']['content-length'] = 17
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: 'Body' object has no attribute 'chunked'"
        )

        # Body.chunked is True:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=True)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'].chunked must be False; got True"
        )

        # Body with 'transfer-encoding' header:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: bodies.Body with 'transfer-encoding' header"
        )

        # Body.content_length attribute is missing:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: 'Body' object has no attribute 'content_length'"
        )

        # Body without 'content-length' header:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False, content_length=17)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: bodies.Body, but missing 'content-length' header"
        )

        # Body.content_length != headers['content-length']:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False, content_length=17)
        bad['headers']['content-length'] = 16
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'].content_length != request['headers']['content-length']: 17 != 16"
        )

        # Body missing 'closed' attribute:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False, content_length=17)
        bad['headers']['content-length'] = 17
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: 'Body' object has no attribute 'closed'"
        )

        # Body.closed must be False prior to calling the application:
        bad = deepcopy(good)
        bad['body'] = Body(chunked=False, content_length=17, closed=True)
        bad['headers']['content-length'] = 17
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'].closed must be False; got True"
        )

        # Methods that should work when request['body'] is a Body instance:
        for method in ('PUT', 'POST'):
            request = deepcopy(good)
            request['method'] = method
            request['body'] = Body(closed=False, chunked=False, content_length=17)
            request['headers']['content-length'] = 17
            self.assertIsNone(rgi._validate_request(default_bodies, request))

        # Methods that should *not* work when request['body'] is a Body instance:
        for method in ('GET', 'HEAD', 'DELETE'):
            request = deepcopy(good)
            request['method'] = method
            request['body'] = Body(closed=False, chunked=False, content_length=17)
            request['headers']['content-length'] = 17
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(default_bodies, request)
            self.assertEqual(str(cm.exception),
                "request['method'] cannot be {!r} when request['body'] is not None".format(method)
            )

        ##############################################
        # request['body'] is a `ChunkedBody` instance:

        # ChunkedBody is missing 'chunked' attribute:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(closed=False)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: 'ChunkedBody' object has no attribute 'chunked'"
        )

        # ChunkedBody.chunked is False:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(closed=False, chunked=False)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'].chunked must be True; got False"
        )

        # ChunkedBody with 'content-length' header:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(chunked=True, closed=False)
        bad['headers']['content-length'] = 17
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: bodies.ChunkedBody with 'content-length' header"
        )

        # ChunkedBody without 'transfer-encoding' header:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(chunked=True, closed=False)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: bodies.ChunkedBody, but missing 'transfer-encoding' header"
        )

        # ChunkedBody is missing 'closed' attribute:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(chunked=True)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body']: 'ChunkedBody' object has no attribute 'closed'"
        )

        # ChunkedBody.closed must be False prior to calling the application:
        bad = deepcopy(good)
        bad['body'] = ChunkedBody(chunked=True, closed=True)
        bad['headers']['transfer-encoding'] = 'chunked'
        with self.assertRaises(ValueError) as cm:
            rgi._validate_request(default_bodies, bad)
        self.assertEqual(str(cm.exception),
            "request['body'].closed must be False; got True"
        )

        # Methods that should work when request['body'] is a ChunkedBody instance:
        for method in ('PUT', 'POST'):
            request = deepcopy(good)
            request['method'] = method
            request['body'] = ChunkedBody(closed=False, chunked=True)
            request['headers']['transfer-encoding'] = 'chunked'
            self.assertIsNone(rgi._validate_request(default_bodies, request))

        # Methods that should *not* work when request['body'] is a ChunkedBody instance:
        for method in ('GET', 'HEAD', 'DELETE'):
            request = deepcopy(good)
            request['method'] = method
            request['body'] = ChunkedBody(closed=False, chunked=True)
            request['headers']['transfer-encoding'] = 'chunked'
            with self.assertRaises(ValueError) as cm:
                rgi._validate_request(default_bodies, request)
            self.assertEqual(str(cm.exception),
                "request['method'] cannot be {!r} when request['body'] is not None".format(method)
            )

    def test_validate_response(self):
        # Validator.__call__() will pass in the *bodies* argument, by which the
        # the Body, BodyIter, ChunkedBody, and ChunkedBodyIter classes are
        # exposed in a server-agnostic fashion.

        request = {
            'method': 'GET',
            'script': ['foo'],
            'path': ['bar'],
            'query': '',
            'body': None,
        }

        # response isn't a `tuple`:
        bad = [200, 'OK', {}, None]
        with self.assertRaises(TypeError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('response', tuple, list, bad)
        )

        # len(response) != 4:
        bad = (200, 'OK', {})
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception), 'len(response) must be 4, got 3')
        bad = (200, 'OK', {}, None, None)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception), 'len(response) must be 4, got 5')

        # response status isn't an int:
        bad = ('200', 'OK', {}, None)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('response[0]', int, str, '200')
        )

        # response status < 100:
        bad = (99, 'OK', {}, None)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            'response[0]: need 100 <= status <= 599; got 99'
        )

        # response status > 599:
        bad = (600, 'OK', {}, None)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            'response[0]: need 100 <= status <= 599; got 600'
        )

        # Test all valid response status:
        for status in range(100, 600):
            self.assertTrue(100 <= status <= 599)
            good = (status, 'OK', {}, None)
            self.assertIsNone(
                rgi._validate_response(default_bodies, deepcopy(request), good)
            )

        # response reason isn't an str:
        bad = (200, b'OK', {}, None)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('response[1]', str, bytes, b'OK')
        )

        # response reason is empty:
        bad = (200, '', {}, None)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            "response[1]: reason cannot be an empty ''"
        )

        # response headers isn't a dict:
        bad = (200, 'OK', [('foo', 'BAR')], None)
        with self.assertRaises(TypeError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            rgi.TYPE_ERROR.format('response[2]', dict, list, [('foo', 'BAR')])
        )

        # request method is 'HEAD', but response headers include neither
        # 'content-length' nor 'transfer-encoding'
        r = deepcopy(request)
        r['method'] = 'HEAD'
        bad = (200, 'OK', {}, None)
        with self.assertRaises(ValueError) as cm:
            rgi._validate_response(default_bodies, r, bad)
        self.assertEqual(str(cm.exception),
            "response[2]: response to HEAD request must include 'content-length' or 'transfer-encoding' header"
        )

        # Test valid responses to 'HEAD' request:
        r = deepcopy(request)
        r['method'] = 'HEAD'
        good = (200, 'OK', {'content-length': 17}, None)
        self.assertIsNone(rgi._validate_response(default_bodies, r, good))
        r = deepcopy(request)
        r['method'] = 'HEAD'
        good = (200, 'OK', {'transfer-encoding': 'chunked'}, None)
        self.assertIsNone(rgi._validate_response(default_bodies, r, good))

        # bad response body type:
        bad = (200, 'OK', {}, 'hello')
        with self.assertRaises(TypeError) as cm:
            rgi._validate_response(default_bodies, deepcopy(request), bad)
        self.assertEqual(str(cm.exception),
            'response[3]: bad response body type: {!r}'.format(str)
        )

        # 'HEAD' request, but response body isn't None:
        bad_bodies = (
            b'D' * 17,
            bytearray(b'D' * 17),
            Body(closed=False, chunked=False, content_length=17),
            BodyIter(closed=False, chunked=False, content_length=17),
            ChunkedBody(closed=False, chunked=False),
            ChunkedBodyIter(closed=False, chunked=False),
        )
        for body in bad_bodies:
            r = deepcopy(request)
            r['method'] = 'HEAD'
            if isinstance(body, (ChunkedBody, ChunkedBodyIter)):
                headers = {'transfer-encoding': 'chunked'}
            else:
                headers = {'content-length': 17}
            bad = (200, 'OK', headers, body)
            with self.assertRaises(TypeError) as cm:
                rgi._validate_response(default_bodies, r, bad)
            self.assertEqual(str(cm.exception),
                "response[3]: must be None when request['method'] is 'HEAD'; got a {!r}".format(
                    type(body)
                )
            )

        # response body is None, but 'content-length' or 'transfer-encoding'
        # header is included:
        bad_headers = (
            ('content-length', 17),
            ('transfer-encoding', 'chunked'),
        )
        for (k, v) in bad_headers:
            bad = (200, 'OK', {k: v}, None)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                '{}: response body is None, but {!r} header is included'.format(
                    'response[3]', k
                )
            )

        # response body is (bytes, bytarray, Body, BodyIter), but
        # 'transfer-encoding' header included:
        bad_bodies = (
            b'hello',
            bytearray(b'hello'),
            Body(content_length=5, chunked=False, closed=True),
            BodyIter(content_length=5, chunked=False, closed=True),
        )
        for body in bad_bodies:
            bad = (200, 'OK', {'transfer-encoding': 'chunked'}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                '{}: response body is {!r}, but {!r} header is included'.format(
                    'response[3]', type(body), 'transfer-encoding'
                )
            )

        # length mismatch when body is (bytes, bytearray):
        for body in (b'hello', bytearray(b'hello')):
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: len(body) is 5, but 'content-length' is 17"
            )

        # response body is (bytes, bytearray), but 'content-length' header is 
        # missing (should be filled in by server before writing response):
        for body in (b'hello', bytearray(b'hello')):
            good = (200, 'OK', {}, body)
            self.assertIsNone(
                rgi._validate_response(default_bodies, deepcopy(request), good)
            )

        # response body is (Body, BodyIter), but missing 'content_length'
        # attribute:
        for klass in (Body, BodyIter):
            body = klass(chunked=False, closed=False)
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: {!r} object has no attribute 'content_length'".format(
                    klass.__name__
                )
            )

        # length mismatch when body is (Body, BodyIter):
        for klass in (Body, BodyIter):
            body = klass(chunked=False, closed=False, content_length=18)
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: body.content_length is 18, but 'content-length' is 17"
            )

        # response body is (Body, BodyIter), but 'content-length' header is 
        # missing (should be filled in by server before writing response):
        for klass in (Body, BodyIter):
            body = klass(chunked=False, closed=False, content_length=18)
            good = (200, 'OK', {}, body)
            self.assertIsNone(
                rgi._validate_response(default_bodies, deepcopy(request), good)
            )

        # response body is (Body, BodyIter), but missing 'chunked' attribute:
        for klass in (Body, BodyIter):
            body = klass(closed=False, content_length=17)
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: {!r} object has no attribute 'chunked'".format(
                    klass.__name__
                )
            )

        # response body is (Body, BodyIter), but body.chunked is True:
        for klass in (Body, BodyIter):
            body = klass(chunked=True, closed=False, content_length=17)
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                'response[3].chunked must be False; got True'
            )

        # response body is (ChunkedBody, ChunkedBodyIter), but 'content-length'
        # header is included:
        for klass in (ChunkedBody, ChunkedBodyIter):
            body = klass(closed=False, chunked=True)
            bad = (200, 'OK', {'content-length': 17}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                '{}: response body is {!r}, but {!r} header is included'.format(
                    'response[3]', klass, 'content-length'
                )
            )

        # response body is (ChunkedBody, ChunkedBodyIter), but
        # 'transfer-encoding' header is missing (should be filled in by server
        # before writing response):
        for klass in (ChunkedBody, ChunkedBodyIter):
            body = klass(chunked=True, closed=False)
            good = (200, 'OK', {}, body)
            self.assertIsNone(
                rgi._validate_response(default_bodies, deepcopy(request), good)
            )

        # response body is (ChunkedBody, ChunkedBodyIter), but missing 'chunked'
        # attribute:
        for klass in (ChunkedBody, ChunkedBodyIter):
            body = klass(closed=False)
            bad = (200, 'OK', {'transfer-encoding': 'chunked'}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: {!r} object has no attribute 'chunked'".format(
                    klass.__name__
                )
            )

        # response body is (ChunkedBody, ChunkedBodyIter), but body.chunked is
        # False:
        for klass in (ChunkedBody, ChunkedBodyIter):
            body = klass(chunked=False, closed=False)
            bad = (200, 'OK', {'transfer-encoding': 'chunked'}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                'response[3].chunked must be True; got False'
            )

        # When response body is (ChunkedBody, ChunkedBodyIter), should not have
        # a 'content_length' attribute:
        for klass in (ChunkedBody, ChunkedBodyIter):
            body = klass(chunked=True, closed=False, content_length=17)
            bad = (200, 'OK', {'transfer-encoding': 'chunked'}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: {!r} must not have a 'content_length' attribute".format(
                    klass
                )
            )

        # response body is (Body, BodyIter, ChunkedBody, ChunkedBodyIter),
        # but missing 'closed' attribute:
        bad_bodies = (
            Body(chunked=False, content_length=17),
            BodyIter(chunked=False, content_length=17),
            ChunkedBody(chunked=True),
            ChunkedBodyIter(chunked=True),
        )
        for body in bad_bodies:
            bad = (200, 'OK', {}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3]: {!r} object has no attribute 'closed'".format(
                    type(body).__name__
                )
            )

        # response body is (Body, BodyIter, ChunkedBody, ChunkedBodyIter),
        # but body.closed is True:
        bad_bodies = (
            Body(closed=True, chunked=False, content_length=17),
            BodyIter(closed=True, chunked=False, content_length=17),
            ChunkedBody(closed=True, chunked=True),
            ChunkedBodyIter(closed=True, chunked=True),
        )
        for body in bad_bodies:
            bad = (200, 'OK', {}, body)
            with self.assertRaises(ValueError) as cm:
                rgi._validate_response(default_bodies, deepcopy(request), bad)
            self.assertEqual(str(cm.exception),
                "response[3].closed must be False; got True"
            )


class TestValidator(TestCase):
    def test_init(self):
        # app not callable:
        class Bad:
            pass

        bad = Bad()
        with self.assertRaises(TypeError) as cm:
            rgi.Validator(bad)
        self.assertEqual(str(cm.exception),
            'app: not callable: {!r}'.format(bad)
        )

        # app.on_connect not callable:
        class Bad:
            def __init__(self):
                self.on_connect = random_identifier()

            def __call__(self, session, request):
                return (200, 'OK', {}, None)

        bad = Bad()
        with self.assertRaises(TypeError) as cm:
            rgi.Validator(bad)
        self.assertEqual(str(cm.exception),
            'app.on_connect: not callable: {!r}'.format(bad.on_connect)
        )

        # app is callable, no on_connect attribute:
        def good_app(session, request):
            return (200, 'OK', {}, None)

        inst = rgi.Validator(good_app)
        self.assertIs(inst.app, good_app)
        self.assertIsNone(inst._on_connect)

        # app is callable, on_connect attribute is None:
        class GoodApp:
            def __init__(self):
                self.on_connect = None

            def __call__(self, session, request):
                return (200, 'OK', {}, None)

        good_app = GoodApp()
        inst = rgi.Validator(good_app)
        self.assertIs(inst.app, good_app)
        self.assertIsNone(inst._on_connect)

        #app is callable, on_connect attribute also callable:
        class GoodApp:
            def __call__(self, session, request):
                return (200, 'OK', {}, None)

            def on_connect(self, sock, session):
                return True

        good_app = GoodApp()
        inst = rgi.Validator(good_app)
        self.assertIs(inst.app, good_app)
        self.assertEqual(inst._on_connect, good_app.on_connect)

    def test_repr(self):
        def my_app(session, request):
            return (200, 'OK', {'x-msg': 'hello, world'}, None)

        inst = rgi.Validator(my_app)
        self.assertEqual(repr(inst), 'Validator({!r})'.format(my_app))

        class Example(rgi.Validator):
            pass

        inst = Example(my_app)
        self.assertEqual(repr(inst), 'Example({!r})'.format(my_app))

    def test_call(self):
        # request['body'].closed is not True after app() was called:
        def my_app(session, request, bodies):
            return (200, 'OK', {}, None)

        inst = rgi.Validator(my_app)
        session = build_session()
        request = build_request(
            body=Body(closed=False, chunked=False, content_length=17),
            headers={'content-length': 17},
        )
        with self.assertRaises(ValueError) as cm:
            inst(session, request, default_bodies)
        self.assertEqual(str(cm.exception),
            "request['body'].closed must be True after app() was called; got False"
        )

        # request['body'].closed is True after app() is called:
        def my_app(session, request, bodies):
            request['body'].closed = True
            return (200, 'OK', {}, None)

        inst = rgi.Validator(my_app)
        session = build_session()
        request = build_request(
            body=Body(closed=False, chunked=False, content_length=17),
            headers={'content-length': 17},
        )
        self.assertEqual(inst(session, request, default_bodies),
            (200, 'OK', {}, None)
        )

    def test_on_connect(self):
        class App:
            def __init__(self, allow):
                self.__allow = allow

            def __call__(self, session, request):
                raise Exception('should not be called')

            def on_connect(self, sock, session):
                if isinstance(self.__allow, Exception):
                    raise self.__allow
                return self.__allow

        # app.on_connect() doesn't return a bool:
        inst = rgi.Validator(App(1))
        session = build_session()
        with self.assertRaises(TypeError) as cm:
            inst.on_connect(None, session)
        self.assertEqual(str(cm.exception),
            "app.on_connect() must return a <class 'bool'>; got a <class 'int'>: 1"
        )
        inst = rgi.Validator(App('true'))
        session = build_session()
        with self.assertRaises(TypeError) as cm:
            inst.on_connect(None, session)
        self.assertEqual(str(cm.exception),
            "app.on_connect() must return a <class 'bool'>; got a <class 'str'>: 'true'"
        )

        # app.on_connect() raises an Exception:
        marker = random_identifier()
        inst = rgi.Validator(App(ValueError(marker)))
        session = build_session()
        with self.assertRaises(ValueError) as cm:
            inst.on_connect(None, session)
        self.assertEqual(str(cm.exception), marker)

        # app.on_connect() returns True:
        inst = rgi.Validator(App(True))
        session = build_session()
        self.assertIs(inst.on_connect(None, session), True)

        # app.on_connect() returns True, but session['requests'] != 0:
        inst = rgi.Validator(App(True))
        session = build_session(requests=1)
        with self.assertRaises(ValueError) as cm:
            inst.on_connect(None, session)
        self.assertEqual(str(cm.exception), 
            "session['requests'] must be 0 when app.on_connect() is called; got 1"
        )

        # app.on_connect() returns False:
        inst = rgi.Validator(App(False))
        session = build_session()
        self.assertIs(inst.on_connect(None, session), False)

        # app.on_connect() returns False, but session['requests'] != 0:
        inst = rgi.Validator(App(False))
        session = build_session(requests=3)
        with self.assertRaises(ValueError) as cm:
            inst.on_connect(None, session)
        self.assertEqual(str(cm.exception), 
            "session['requests'] must be 0 when app.on_connect() is called; got 3"
        )

        # app has no 'on_connect' attribute:
        def my_app(session, request):
            raise Exception('should not be called')

        inst = rgi.Validator(my_app)
        session = build_session()
        self.assertIs(inst.on_connect(None, session), True)

        # app.on_connect is None:
        my_app.on_connect = None
        inst = rgi.Validator(my_app)
        session = build_session()
        self.assertIs(inst.on_connect(None, session), True)

