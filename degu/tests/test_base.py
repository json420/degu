# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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
Unit tests for the `degu.base` module.
"""

from unittest import TestCase
import os
import io
import sys
from random import SystemRandom
import types
from collections import OrderedDict

from .helpers import (
    random_chunks,
    iter_bad,
    random_chunks2,
    random_chunk,
    random_data,
    iter_random_uri,
    iter_good,
    MockSocket,
)
from degu.sslhelpers import random_id
from degu.misc import mkreq
from degu import base, _basepy


# True if the C extension is available
try:
    from degu import _base
    C_EXT_AVAIL = True
except ImportError:
    _base = None
    C_EXT_AVAIL = False


random = SystemRandom()


# Subclasses to check that strict type checking is done:
class UserInt(int):
    pass

class UserStr(str):
    pass

class UserBytes(bytes):
    pass


MAX_LENGTH = int('9' * 16)
MAX_UINT64 = 2**64 - 1
assert 0 < MAX_LENGTH < MAX_UINT64
BAD_LENGTHS = (
    -MAX_UINT64 - 1,
    -MAX_UINT64,
    -MAX_LENGTH - 1,
    -MAX_LENGTH,
    -17,
    -1,
    MAX_LENGTH + 1,
    MAX_UINT64,
    MAX_UINT64 + 1,
)
CRLF = b'\r\n'
TERM = CRLF * 2
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'
TYPE_ERROR2 = '{}: need a {!r}; got a {!r}'

BAD_HEADER_LINES = (
    b'K:V\r\n',
    b'K V\r\n',
    b': V\r\n',
    b'K: \r\n',
    b': \r\n',
)

GOOD_HEADERS = (
    (
        b'Content-Type: application/json\r\n',
        ('content-type', 'application/json')
    ),
    (
        b'Content-Length: 17\r\n',
        ('content-length', 17)
    ),
    (
        b'Content-Length: 0\r\n',
        ('content-length', 0)
    ),
    (
        b'Transfer-Encoding: chunked\r\n',
        ('transfer-encoding', 'chunked')
    ),
    (
        b'User-Agent: Microfiber/14.12.0 (Ubuntu 14.04; x86_64)\r\n',
        ('user-agent', 'Microfiber/14.12.0 (Ubuntu 14.04; x86_64)')
    ),
    (
        b'Host: 192.168.1.171:5984\r\n',
        ('host', '192.168.1.171:5984')
    ),
    (
        b'Host: [fe80::e8b:fdff:fe75:402c/64]:5984\r\n',
        ('host', '[fe80::e8b:fdff:fe75:402c/64]:5984')
    ),
    (
        b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
        ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
    ),
    (
        b'Date: Sat, 27 Dec 2014 01:12:48 GMT\r\n',
        ('date', 'Sat, 27 Dec 2014 01:12:48 GMT')
    ),
    (
        b'Content-Type: text/html;charset=utf-8\r\n',
        ('content-type', 'text/html;charset=utf-8')
    ),
)

OUTGOING_KEY = bytes(_basepy.KEY).decode()
OUTGOING_VAL = bytes(_basepy.VAL).decode()
STR256 = bytes(range(256)).decode('latin1')
BAD_OUTGOING_KEY = ''.join(set(STR256) - set(OUTGOING_KEY)) + '¡™'

def random_key(size):
    return ''.join(random.choice(OUTGOING_KEY) for i in range(size))

def random_val(size):
    return ''.join(random.choice(OUTGOING_VAL) for i in range(size))

def iter_bad_keys():
    yield ''
    yield '¡™'
    good = random_key(32)
    for i in range(len(good)):
        bad = list(good)
        for b in BAD_OUTGOING_KEY:
            bad[i] = b
            yield ''.join(bad)


def _permute_remove(method):
    if len(method) <= 1:
        return
    for i in range(len(method)):
        m = bytearray(method)
        del m[i]
        m = bytes(m)
        yield m
        yield from _permute_remove(m)


def _permute_replace(method):
    for i in range(len(method)):
        for j in range(256):
            if method[i] == j:
                continue
            m = bytearray(method)
            m[i] = j
            yield bytes(m)


def _permute_insert(method):
    for i in range(len(method) + 1):
        for j in range(256):
            m = bytearray(method)
            m.insert(i, j)
            yield bytes(m)


GOOD_METHODS = (
    'GET',
    'PUT',
    'POST',
    'HEAD',
    'DELETE',
)
BAD_METHODS = [
    '',
    'TRACE',
    'OPTIONS',
    'CONNECT',
    'PATCH',
    'GOT',
    'POT',
    'PUSH',
    'HELL',
    'REPEAT',
]
BAD_METHODS.extend(m.lower() for m in GOOD_METHODS)
BAD_METHODS = tuple(BAD_METHODS)

BAD_METHODS_BYTES = []
for func in (_permute_remove, _permute_replace, _permute_insert):
    for m in GOOD_METHODS:
        BAD_METHODS_BYTES.extend(func(m.encode()))
BAD_METHODS_BYTES.extend(m.encode() for m in BAD_METHODS)
BAD_METHODS_BYTES = tuple(sorted(set(BAD_METHODS_BYTES)))


# Pre-build bad preamble termination permutations:
def _iter_bad_term(term):
    for i in range(len(term)):
        bad = bytearray(term)
        del bad[i]
        yield bytes(bad)
        g = term[i]
        for b in range(256):
            if b == g:
                continue
            bad = bytearray(term)
            bad[i] = b
            yield bytes(bad)

BAD_TERM = tuple(_iter_bad_term(b'\r\n\r\n'))


def random_headers(count):
    return dict(
        ('X-' + random_id(), random_id()) for i in range(count)
    )


def build_header_lines(headers):
    return ''.join(
        '{}: {}\r\n'.format(key, value) for (key, value) in headers.items()
    ).encode('latin_1')


def casefold_headers(headers):
    """
    For example:

    >>> casefold_headers({'FOO': 'BAR'})
    {'foo': 'BAR'}

    """
    return dict(
        (key.casefold(), value) for (key, value) in headers.items()
    )


def random_line():
    return '{}\r\n'.format(random_id()).encode()


def random_header_line():
    return '{}: {}\r\n'.format(random_id(), random_id()).encode()


def random_lines(header_count=15):
    first_line = random_id()
    header_lines = [random_id() for i in range(header_count)]
    return (first_line, header_lines)


def encode_preamble(first_line, header_lines):
    lines = [first_line + '\r\n']
    lines.extend(line + '\r\n' for line in header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode('latin_1')


def random_body():
    size = random.randint(1, 34969)
    return os.urandom(size)


def get_module_attr(mod, name):
    assert type(mod) is types.ModuleType
    if not hasattr(mod, name):
        raise AttributeError(
            '{!r} module has no attribute {!r}'.format(mod.__name__, name)
        )
    return getattr(mod, name)


class TestAliases(TestCase):
    """
    Ensure alias objects in `degu.base` are from the expected backend module.
    """

    def check(self, name):
        got = get_module_attr(base, name)
        backend = (_base if C_EXT_AVAIL else _basepy)
        expected = get_module_attr(backend, name)
        self.assertIs(got, expected, name)

    def test_all(self):
        all_names = (
            'EmptyPreambleError',
            'API',      'APIType',
            'Response', 'ResponseType',
            'Range',
            'ContentRange',
            'Request',
            'api',
            'Connection',
            'Session',
            '_handle_requests',
        )
        self.assertEqual(sorted(set(all_names)), sorted(all_names))
        self.assertEqual(all_names, base.__all__)
        for name in all_names:
            self.check(name)


ARG_MSG_C = '{}() requires {} arguments; got {}'
ARG_MSG_Py_1 = '{}() missing 1 required positional argument: {!r}'
ARG_MSG_Py_2 = '{}() takes {} positional arguments but {} were given'


class BackendTestCase(TestCase):
    backend = _basepy

    def setUp(self):
        backend = self.backend
        name = self.__class__.__name__
        if name.endswith('_Py'):
            self.assertIs(backend, _basepy)
        elif name.endswith('_C'):
            self.assertIs(backend, _base)
        else:
            raise Exception(
                'bad BackendTestCase subclass name: {!r}'.format(name)
            )
        if backend is None:
            self.skipTest('cannot import `degu._base` C extension')

    def getattr(self, name):
        backend = self.backend
        self.assertIn(backend, (_basepy, _base))
        self.assertIsNotNone(backend)
        if not hasattr(backend, name):
            raise Exception(
                '{!r} has no attribute {!r}'.format(backend.__name__, name)
            )
        # FIXME: check imported alias in degu.base (when needed)
        return getattr(backend, name)

    @property
    def BUF_LEN(self):
        return self.getattr('BUF_LEN')

    @property
    def SCRATCH_LEN(self):
        return self.getattr('SCRATCH_LEN')

    @property
    def MAX_LINE_LEN(self):
        return self.getattr('MAX_LINE_LEN')

    @property
    def MAX_CL_LEN(self):
        return self.getattr('MAX_CL_LEN')

    @property
    def MAX_LENGTH(self):
        return self.getattr('MAX_LENGTH')

    @property
    def IO_SIZE(self):
        return self.getattr('IO_SIZE')

    @property
    def MAX_IO_SIZE(self):
        return self.getattr('MAX_IO_SIZE')

    @property
    def MAX_HEADER_COUNT(self):
        return self.getattr('MAX_HEADER_COUNT')

    @property
    def EmptyPreambleError(self):
        return self.getattr('EmptyPreambleError')

    @property
    def api(self):
        return self.getattr('api')

    @property
    def Request(self):
        return self.getattr('Request')

    def mkreq(self, uri, headers=None, body=None, shift=0):
        return mkreq(uri, headers, body, shift, cls=self.Request)

    def check_args(self, cobj, name, number, missing, fullname):
        assert isinstance(number, int) and number > 0
        args1 = tuple(random_id() for i in range(number - 1))
        args2 = tuple(random_id() for i in range(number + 1))
        for args in (args1, args2):
            with self.assertRaises(TypeError) as cm:
                cobj(*args)
            if self.backend is _base:
                msg = ARG_MSG_C.format(fullname, number, len(args))
            elif len(args) < number:
                msg = ARG_MSG_Py_1.format(name, missing)
            else:
                msg = ARG_MSG_Py_2.format(name, number + 1, number + 2)
            self.assertEqual(str(cm.exception), msg)

    def check_method_args(self, inst, name, number, missing):
        method = getattr(inst, name)
        fullname = '.'.join([inst.__class__.__name__, name])
        self.check_args(method, name, number, missing, fullname)

    def check_init_args(self, cls, number, missing):
        name = '__init__'
        fullname = '.'.join([cls.__name__, name])
        self.check_args(cls, name, number, missing, fullname)

REQUEST_ARGS_REPR = ', '.join([
    'method={!r}',  # method
    'uri={!r}',  # uri
    'headers={!r}',  # headers
    'body={!r}',  # body
    'mount={!r}',
    'path={!r}',
    'query={!r}',
])


class TestRequest_Py(BackendTestCase):
    @property
    def Request(self):
        return self.getattr('Request')

    def iter_random_args(self):
        for method in GOOD_METHODS:
            for (uri, path, query) in iter_random_uri():
                yield (method, uri, {}, None, [], path, query)

    def test_init(self):
        # Make sure method type is checked:
        for method in GOOD_METHODS:
            for bad in [method.encode(), UserStr(method)]:
                with self.assertRaises(TypeError) as cm:
                    self.Request(bad, '/', {}, None, [], [], None)
                self.assertEqual(str(cm.exception),
                    TYPE_ERROR.format('method', str, type(bad), bad)
                )

        # Make sure method value is checked:
        for bad in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:
                self.Request(bad, '/', {}, None, [], [], None)
            self.assertEqual(str(cm.exception), 'bad method: {!r}'.format(bad))

        parse_method = self.getattr('parse_method')
        mp = parse_method('GET')
        request = self.Request('GET', '/', {}, None, [], [], None)
        self.assertIsInstance(request, self.Request)
        self.assertIs(request.method, mp[0])
        self.assertEqual(request.m, mp[1])
        self.assertEqual(request.uri, '/')
        self.assertEqual(request.headers, {})
        self.assertIsNone(request.body)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, [])
        self.assertIsNone(request.query)

        with self.assertRaises(TypeError) as cm:
            self.Request('GET', '/', {}, None, tuple(), [], None)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR2.format('mount', list, tuple)
        )
        with self.assertRaises(TypeError) as cm:
            self.Request('GET', '/', {}, None, [], tuple(), None)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR2.format('path', list, tuple)
        )

        for args in self.iter_random_args():
            mp = parse_method(args[0])
            request = self.Request(*args)
            self.assertIsInstance(request, self.Request)
            self.assertIs(request.method,  mp[0])
            self.assertEqual(request.m,    mp[1])
            self.assertIs(request.uri,     args[1])
            self.assertIs(request.headers, args[2])
            self.assertIs(request.body,    args[3])
            self.assertIs(request.mount,   args[4])
            self.assertIs(request.path,    args[5])
            self.assertIs(request.query,   args[6])
            args_repr = REQUEST_ARGS_REPR.format(*args)
            self.assertEqual(repr(request), 'Request({})'.format(args_repr))

        # Test refrences counting:
        args = (
            b'GET / HTTP/1.1'.decode()[0:3],
            random_id(),
            {random_id(): random_id()},
            random_id(),
            [],
            [random_id(), random_id()],
            random_id(),
        )
        for i in range(len(args)):
            self.assertEqual(sys.getrefcount(args[i]), 2)
        request = self.Request(*args)
        for i in range(len(args)):
            count = (2 if i == 0 else 3)
            self.assertEqual(sys.getrefcount(args[i]), count)
        del request
        for i in range(len(args)):
            self.assertEqual(sys.getrefcount(args[i]), 2)

        # Attributes should be read-only:
        request = self.Request(*args)
        attributes = (
            'method',
            'm',
            'uri',
            'headers',
            'body',
            'mount',
            'path',
            'query',
        )
        for name in attributes:
            orig = getattr(request, name)
            with self.assertRaises(AttributeError):
                setattr(request, name, random_id())
            self.assertIs(getattr(request, name), orig)
            del orig
        del request
        for i in range(len(args)):
            self.assertEqual(sys.getrefcount(args[i]), 2)

    def test_shift_path(self):
        def mk_request(mount, path):
            return self.Request('GET', '/', {}, None, mount, path, None)

        # both mount and path are empty:
        mount = []
        path = []
        request = mk_request(mount, path)
        self.assertIsNone(request.shift_path())
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, [])
        del request
        self.assertEqual(sys.getrefcount(mount), 2)
        self.assertEqual(sys.getrefcount(path), 2)

        # path is empty:
        mount = ['foo']
        path = []
        request = mk_request(mount, path)
        self.assertIsNone(request.shift_path())
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, ['foo'])
        self.assertEqual(request.path, [])
        del request
        self.assertEqual(sys.getrefcount(mount), 2)
        self.assertEqual(sys.getrefcount(path), 2)

        # start with populated path:
        items = tuple(random_id() for i in range(3))
        mount = []
        path = list(items)
        request = mk_request(mount, path)
        self.assertEqual(request.shift_path(), items[0])
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, list(items[0:1]))
        self.assertEqual(request.path, list(items[1:3]))

        self.assertEqual(request.shift_path(), items[1])
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, list(items[0:2]))
        self.assertEqual(request.path, list(items[2:3]))

        self.assertEqual(request.shift_path(), items[2])
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, list(items))
        self.assertEqual(request.path, [])

        self.assertIsNone(request.shift_path())
        self.assertIs(request.mount, mount)
        self.assertIs(request.path, path)
        self.assertEqual(request.mount, list(items))
        self.assertEqual(request.path, [])

        self.assertEqual(sys.getrefcount(mount), 3)
        self.assertEqual(sys.getrefcount(path), 3)
        self.assertEqual(sys.getrefcount(items[0]), 3)
        self.assertEqual(sys.getrefcount(items[1]), 3)
        self.assertEqual(sys.getrefcount(items[2]), 3)
        del request
        self.assertEqual(sys.getrefcount(mount), 2)
        self.assertEqual(sys.getrefcount(path), 2)
        self.assertEqual(sys.getrefcount(items[0]), 3)
        self.assertEqual(sys.getrefcount(items[1]), 3)
        self.assertEqual(sys.getrefcount(items[2]), 3)
        del mount
        del path
        self.assertEqual(sys.getrefcount(items[0]), 2)
        self.assertEqual(sys.getrefcount(items[1]), 2)
        self.assertEqual(sys.getrefcount(items[2]), 2)

    def test_build_proxy_uri(self):
        def mk_request(path, query):
            return self.Request('GET', '/', {}, None, [], path, query)

        path_permutations = (
            (tuple(),            '/'),
            (('',),              '/'),
            (('foo',),           '/foo'),
            (('foo', ''),        '/foo/'),
            (('foo', 'bar'),     '/foo/bar'),
            (('foo', 'bar', ''), '/foo/bar/'),
        )
        query_permutations = (
            (None,      ''),
            ('',        '?'),
            ('foo',     '?foo'),
            ('foo=bar', '?foo=bar'),
        )
        for (path, uri) in path_permutations:
            request = mk_request(list(path), None)
            self.assertEqual(request.build_proxy_uri(), uri)
            self.assertEqual(request.path, list(path))
        for (query, end) in query_permutations:
            request = mk_request([], query)
            self.assertEqual(request.build_proxy_uri(), '/' + end)
            self.assertEqual(request.path, [])
        for (path, uri) in path_permutations:
            for (query, end) in query_permutations:
                request = mk_request(list(path), query)
                self.assertEqual(request.build_proxy_uri(), uri + end)
                self.assertEqual(request.path, list(path))

        # path is empty:
        request = mk_request([], None)
        self.assertEqual(request.build_proxy_uri(), '/')
        self.assertEqual(request.path, [])

        request = mk_request([], '')
        self.assertEqual(request.build_proxy_uri(), '/?')
        self.assertEqual(request.path, [])

        request = mk_request([], 'foo')
        self.assertEqual(request.build_proxy_uri(), '/?foo')
        self.assertEqual(request.path, [])

        request = mk_request([], 'foo=bar')
        self.assertEqual(request.build_proxy_uri(), '/?foo=bar')
        self.assertEqual(request.path, [])

        # No query
        request = mk_request([''], None)
        self.assertEqual(request.build_proxy_uri(), '/')
        self.assertEqual(request.path, [''])

        request = mk_request(['foo'], None)
        self.assertEqual(request.build_proxy_uri(), '/foo')
        self.assertEqual(request.path, ['foo'])

        request = mk_request(['foo', ''], None)
        self.assertEqual(request.build_proxy_uri(), '/foo/')
        self.assertEqual(request.path, ['foo', ''])

        request = mk_request(['foo', 'bar'], None)
        self.assertEqual(request.build_proxy_uri(), '/foo/bar')
        self.assertEqual(request.path, ['foo', 'bar'])

        request = mk_request(['foo', 'bar', ''], None)
        self.assertEqual(request.build_proxy_uri(), '/foo/bar/')
        self.assertEqual(request.path, ['foo', 'bar', ''])


class TestRequest_C(TestRequest_Py):
    backend = _base


class TestRange_Py(BackendTestCase):
    @property
    def Range(self):
        return self.getattr('Range')

    def test_init(self):
        self.check_init_args(self.Range, 2, 'stop')

        # start isn't an int:
        for bad in ['16', 16.0, UserInt(16), None]:
            with self.assertRaises(TypeError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('start', int, type(bad), bad)
            )

        # stop isn't an int:
        for bad in ['21', 21.0, UserInt(21), None]:
            with self.assertRaises(TypeError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('stop', int, type(bad), bad)
            )

        # start < 0, stop < 0:
        for bad in [-1, -2, -9999999999999999]:
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )

        # start > max64, stop > max64:
        max64 = 2**64 - 1
        for offset in [1, 2, 3]:
            bad = max64 + offset
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )

        # start > max_length, stop > max_length:
        max_length = int('9' * 16)
        for bad in [max_length + 1, max_length + 2, max64]:
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {}'.format(bad)
            )

        # start >= stop:
        bad_pairs = (
            (0, 0),
            (1, 0),
            (17, 17),
            (18, 17),
            (9999999999999998, 9999999999999998),
            (9999999999999999, 9999999999999998),
        )
        for (start, stop) in bad_pairs:
            with self.assertRaises(ValueError) as cm:
                self.Range(start, stop)
            self.assertEqual(str(cm.exception),
                'need start < stop; got {} >= {}'.format(start, stop)
            )

        # All good:
        r = self.Range(16, 21)
        self.assertIs(type(r.start), int)
        self.assertIs(type(r.stop), int)
        self.assertEqual(r.start, 16)
        self.assertEqual(r.stop, 21)
        self.assertEqual(repr(r), 'Range(16, 21)')
        self.assertEqual(str(r), 'bytes=16-20')

        r = self.Range(0, max_length)
        self.assertIs(type(r.start), int)
        self.assertIs(type(r.stop), int)
        self.assertEqual(r.start, 0)
        self.assertEqual(r.stop, max_length)
        self.assertEqual(repr(r), 'Range(0, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=0-9999999999999998')

        # Check reference counting:
        if self.backend is _base:
            delmsg = 'readonly attribute'
        else:
            delmsg = "can't delete attribute"
        for i in range(1000):
            stop = random.randrange(1, max_length + 1)
            start = random.randrange(0, stop)
            stop_cnt = sys.getrefcount(stop)
            start_cnt = sys.getrefcount(start)

            r = self.Range(start, stop)
            self.assertIs(type(r.start), int)
            self.assertIs(type(r.stop), int)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(repr(r), 'Range({}, {})'.format(start, stop))
            self.assertEqual(str(r), 'bytes={}-{}'.format(start, stop - 1))
            del r
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)

            # start, stop should be read-only:
            r = self.Range(start, stop)
            for name in ('start', 'stop'):
                with self.assertRaises(AttributeError) as cm:
                    delattr(r, name)
                self.assertEqual(str(cm.exception), delmsg)
            del r
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)

    def test_repr_and_str(self):
        r = self.Range(0, 1)
        self.assertEqual(repr(r), 'Range(0, 1)')
        self.assertEqual(str(r),  'bytes=0-0')

        r = self.Range(0, 9999999999999999)
        self.assertEqual(repr(r), 'Range(0, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=0-9999999999999998')

        r = self.Range(9999999999999998, 9999999999999999)
        self.assertEqual(repr(r), 'Range(9999999999999998, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=9999999999999998-9999999999999998')

    def test_cmp(self):
        def iter_types(pairs):
            for (start, stop) in pairs:
                yield self.Range(start, stop)
                yield 'bytes={}-{}'.format(start, stop - 1)

        def iter_swaps(this, others):
            for o in others:
                yield (this, o)
                yield (o, this)

        r = self.Range(16, 21)
        equals   = tuple(iter_types([(16, 21)]))
        lessers  = tuple(iter_types([(15, 21), (16, 20)]))
        greaters = tuple(iter_types([(17, 21), (16, 22)]))
        notequals = lessers + greaters
        badtypes = ((r.start, r.stop), str(r).encode)
        combined = equals + notequals + badtypes

        # __lt__():
        if self.backend is _base:
            msg = 'unorderable type: Range()'
        else:
            msg = 'unorderable types: {t}() < {o}()'
        for (t, o) in iter_swaps(r, combined):
            with self.assertRaises(TypeError) as cm:
                t < o
            self.assertEqual(str(cm.exception),
                msg.format(
                    t=t.__class__.__name__, o=o.__class__.__name__
                )
            )
        
        # __le__():
        if self.backend is _base:
            msg = 'unorderable type: Range()'
        else:
            msg = 'unorderable types: {t}() <= {o}()'
        for (t, o) in iter_swaps(r, combined):
            with self.assertRaises(TypeError) as cm:
                t <= o
            self.assertEqual(str(cm.exception),
                msg.format(
                    t=t.__class__.__name__, o=o.__class__.__name__
                )
            )

        # __eq__():
        for (t, o) in iter_swaps(r, equals):
            self.assertIs(t == o, True)
        for (t, o) in iter_swaps(r, notequals):
            self.assertIs(t == o, False)

        # __ne__():
        for (t, o) in iter_swaps(r, equals):
            self.assertIs(t != o, False)
        for (t, o) in iter_swaps(r, notequals):
            self.assertIs(t != o, True)

        # __gt__():
        if self.backend is _base:
            msg = 'unorderable type: Range()'
        else:
            msg = 'unorderable types: {t}() > {o}()'
        for (t, o) in iter_swaps(r, combined):
            with self.assertRaises(TypeError) as cm:
                t > o
            self.assertEqual(str(cm.exception),
                msg.format(
                    t=t.__class__.__name__, o=o.__class__.__name__
                )
            )

        # __ge__():
        if self.backend is _base:
            msg = 'unorderable type: Range()'
        else:
            msg = 'unorderable types: {t}() >= {o}()'
        for (t, o) in iter_swaps(r, combined):
            with self.assertRaises(TypeError) as cm:
                t >= o
            self.assertEqual(str(cm.exception),
                msg.format(
                    t=t.__class__.__name__, o=o.__class__.__name__
                )
            )

        # uncomparable types:
        for bad in badtypes:
            msg = 'cannot compare Range() with {!r}'.format(type(bad))
            for (t, o) in [(r, bad), (bad, r)]:
                with self.assertRaises(TypeError) as cm:
                    t == o
                self.assertEqual(str(cm.exception), msg)
                with self.assertRaises(TypeError) as cm:
                    t != o
                self.assertEqual(str(cm.exception), msg)


class TestRange_C(TestRange_Py):
    backend = _base


class TestContentRange_Py(BackendTestCase):
    @property
    def ContentRange(self):
        return self.getattr('ContentRange')

    def test_init(self):
        self.check_init_args(self.ContentRange, 3, 'total')

        # start isn't an int:
        for bad in ['16', 16.0, UserInt(16), None]:
            with self.assertRaises(TypeError) as cm:
                self.ContentRange(bad, 21, 23)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('start', int, type(bad), bad)
            )

        # stop isn't an int:
        for bad in ['21', 21.0, UserInt(21), None]:
            with self.assertRaises(TypeError) as cm:
                self.ContentRange(16, bad, 23)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('stop', int, type(bad), bad)
            )

        # total isn't an int:
        for bad in ['23', 23.0, UserInt(23), None]:
            with self.assertRaises(TypeError) as cm:
                self.ContentRange(16, 21, bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('total', int, type(bad), bad)
            )

        # start < 0, stop < 0, total < 0:
        for bad in [-1, -2, -MAX_LENGTH, -MAX_UINT64]:
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(bad, 21, 32)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(16, bad, 23)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(16, 31, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= total <= 9999999999999999; got {!r}'.format(bad)
            )

        # start > MAX_LENGTH, stop > MAX_LENGTH, total > MAX_LENGTH:
        for bad in [MAX_LENGTH + 1, MAX_UINT64, MAX_UINT64 + 1]:
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(bad, 21, 32)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(16, bad, 23)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(16, 31, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= total <= 9999999999999999; got {!r}'.format(bad)
            )

        # start >= stop or stop > total:
        bad_triplets = (
            (0, 0, 23),
            (1, 0, 23),
            (17, 17, 23),
            (18, 17, 23),
            (MAX_LENGTH - 1, MAX_LENGTH - 1, MAX_LENGTH),
            (MAX_LENGTH, MAX_LENGTH, MAX_LENGTH),
            (0, 18, 17),
            (0, 18, 15),
        )
        for (start, stop, total) in bad_triplets:
            with self.assertRaises(ValueError) as cm:
                self.ContentRange(start, stop, total)
            self.assertEqual(str(cm.exception),
                'need start < stop <= total; got ({}, {}, {})'.format(
                    start, stop, total
                )
            )

        # All good:
        cr = self.ContentRange(0, 1, 1)
        self.assertIs(type(cr.start), int)
        self.assertIs(type(cr.stop), int)
        self.assertIs(type(cr.total), int)
        self.assertEqual(cr.start, 0)
        self.assertEqual(cr.stop, 1)
        self.assertEqual(cr.total, 1)
        self.assertEqual(repr(cr), 'ContentRange(0, 1, 1)')
        self.assertEqual(str(cr), 'bytes 0-0/1')

        cr = self.ContentRange(16, 21, 23)
        self.assertIs(type(cr.start), int)
        self.assertIs(type(cr.stop), int)
        self.assertIs(type(cr.total), int)
        self.assertEqual(cr.start, 16)
        self.assertEqual(cr.stop, 21)
        self.assertEqual(cr.total, 23)
        self.assertEqual(repr(cr), 'ContentRange(16, 21, 23)')
        self.assertEqual(str(cr), 'bytes 16-20/23')

        cr = self.ContentRange(MAX_LENGTH - 1, MAX_LENGTH, MAX_LENGTH)
        self.assertIs(type(cr.start), int)
        self.assertIs(type(cr.stop), int)
        self.assertIs(type(cr.total), int)
        self.assertEqual(cr.start, MAX_LENGTH - 1)
        self.assertEqual(cr.stop, MAX_LENGTH)
        self.assertEqual(cr.total, MAX_LENGTH)
        self.assertEqual(repr(cr),
            'ContentRange(9999999999999998, 9999999999999999, 9999999999999999)'
        )
        self.assertEqual(str(cr),
            'bytes 9999999999999998-9999999999999998/9999999999999999'
        )

        # Check reference counting:
        if self.backend is _base:
            delmsg = 'readonly attribute'
        else:
            delmsg = "can't delete attribute"
        for i in range(1000):
            stop = random.randrange(1, MAX_LENGTH + 1)
            start = random.randrange(0, stop)
            total = random.randrange(stop, MAX_LENGTH + 1)
            start_cnt = sys.getrefcount(start)
            stop_cnt = sys.getrefcount(stop)
            total_cnt = sys.getrefcount(total)

            cr = self.ContentRange(start, stop, total)
            self.assertIs(type(cr.start), int)
            self.assertIs(type(cr.stop), int)
            self.assertIs(type(cr.total), int)
            self.assertEqual(cr.start, start)
            self.assertEqual(cr.stop, stop)
            self.assertEqual(cr.total, total)
            self.assertEqual(repr(cr),
                'ContentRange({}, {}, {})'.format(start, stop, total)
            )
            self.assertEqual(str(cr),
                'bytes {}-{}/{}'.format(start, stop - 1, total)
            )
            del cr
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)
            self.assertEqual(sys.getrefcount(total), total_cnt)

            # start, stop, total should be read-only:
            r = self.ContentRange(start, stop, total)
            for name in ('start', 'stop', 'total'):
                with self.assertRaises(AttributeError) as cm:
                    delattr(r, name)
                self.assertEqual(str(cm.exception), delmsg)
            del r
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)
            self.assertEqual(sys.getrefcount(total), total_cnt)

    def test_repr_and_str(self):
        cr = self.ContentRange(0, 1, 1)
        self.assertEqual(repr(cr), 'ContentRange(0, 1, 1)')
        self.assertEqual(str(cr),  'bytes 0-0/1')

        cr = self.ContentRange(0, 1, MAX_LENGTH)
        self.assertEqual(repr(cr), 'ContentRange(0, 1, 9999999999999999)')
        self.assertEqual(str(cr),  'bytes 0-0/9999999999999999')

        cr = self.ContentRange(0, MAX_LENGTH, MAX_LENGTH)
        self.assertEqual(repr(cr),
            'ContentRange(0, 9999999999999999, 9999999999999999)'
        )
        self.assertEqual(str(cr),  'bytes 0-9999999999999998/9999999999999999')

        cr = self.ContentRange(MAX_LENGTH - 1, MAX_LENGTH, MAX_LENGTH)
        self.assertEqual(repr(cr),
            'ContentRange(9999999999999998, 9999999999999999, 9999999999999999)'
        )
        self.assertEqual(str(cr),
            'bytes 9999999999999998-9999999999999998/9999999999999999'
        )

    def test_cmp(self):
        def iter_types(triplets):
            for (start, stop, total) in triplets:
                yield self.ContentRange(start, stop, total)
                yield 'bytes {}-{}/{}'.format(start, stop - 1, total)

        cr = self.ContentRange(16, 21, 23)
        equals   = tuple(iter_types([(16, 21, 23)]))
        lessers  = tuple(iter_types([(15, 21, 23), (16, 20, 23)]))
        greaters = tuple(iter_types([(17, 21, 23), (16, 22, 23)]))

        # __eq__():
        for o in lessers:
            self.assertIs(cr == o, False)
            self.assertIs(o == cr, False)
        for o in equals:
            self.assertIs(cr == o, True)
            self.assertIs(o == cr, True)
        for o in greaters:
            self.assertIs(cr == o, False)
            self.assertIs(o == cr, False)

        # __ne__():
        for o in lessers:
            self.assertIs(cr != o, True)
            self.assertIs(o != cr, True)
        for o in equals:
            self.assertIs(cr != o, False)
            self.assertIs(o != cr, False)
        for o in greaters:
            self.assertIs(cr != o, True)
            self.assertIs(o != cr, True)

class TestContentRange_C(TestContentRange_Py):
    backend = _base


def _iter_sep_permutations(good=b': '):
    (g0, g1) = good
    yield bytes([g0])
    yield bytes([g1])
    for v in range(256):
        yield bytes([v, g1])
        yield bytes([g0, v])

SEP_PERMUTATIONS = tuple(_iter_sep_permutations())

def _iter_crlf_permutations(good=b'\r\n'):
    (g0, g1) = good
    yield bytes([g0])
    yield bytes([g1])
    for v in range(256):
        yield bytes([v, g1])
        yield bytes([g0, v])

CRLF_PERMUTATIONS = tuple(_iter_crlf_permutations())


class TestParsingFunctions_Py(BackendTestCase):
    def test_parse_content_length(self):
        parse_content_length = self.getattr('parse_content_length')

        # Empty bytes:
        with self.assertRaises(ValueError) as cm:
            parse_content_length(b'')
        self.assertEqual(str(cm.exception), "bad content-length: b''")

        # Too long:
        good = b'1111111111111111'
        bad =  b'11111111111111112'
        self.assertEqual(parse_content_length(good), 1111111111111111)
        with self.assertRaises(ValueError) as cm:
            parse_content_length(bad)
        self.assertEqual(str(cm.exception),
            "content-length too long: b'1111111111111111'..."
        )

        # Too short, just right, too long:
        for size in range(50):
            buf = b'1' * size
            if 1 <= size <= 16:
                self.assertEqual(parse_content_length(buf), int(buf))
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(buf)
                if size == 0:
                    self.assertEqual(str(cm.exception),
                        "bad content-length: b''"
                    )
                else:
                    self.assertEqual(str(cm.exception),
                        "content-length too long: b'1111111111111111'..."
                    )

        # b'0' should work fine:
        self.assertEqual(parse_content_length(b'0'), 0)

        # Non-leading zeros should work fine:
        somegood = (
            b'10',
            b'100',
            b'101',
            b'909',
            b'1000000000000000',
            b'1000000000000001',
            b'9000000000000000',
            b'9000000000000009',
        )
        for good in somegood:
            self.assertEqual(parse_content_length(good), int(good))

        # But leading zeros should raise a ValueError:
        somebad = (
            b'01',
            b'09',
            b'011',
            b'099',
            b'0111111111111111',
            b'0999999999999999',
            b'0000000000000001',
            b'0000000000000009',
        )
        for bad in somebad:
            with self.assertRaises(ValueError) as cm:
                parse_content_length(bad)
            self.assertEqual(str(cm.exception),
                'bad content-length: {!r}'.format(bad)
            )

        # Netative values and spaces are nope:
        somebad = (
            b'-1',
            b'-17',
            b' 1',
            b'1 ',
            b'              -1',
            b'-900719925474099',
        )
        for bad in somebad:
            with self.assertRaises(ValueError) as cm:
                parse_content_length(bad)
            self.assertEqual(str(cm.exception),
                'bad content-length: {!r}'.format(bad)
            )

        # Start with a know good value, then for each possible bad byte value,
        # copy the good value and make it bad by replacing a good byte with a
        # bad byte at each possible index:
        goodset = frozenset(b'0123456789')
        badset = frozenset(range(256)) - goodset
        good = b'9007199254740992'
        self.assertEqual(parse_content_length(good), 9007199254740992)
        for b in badset:
            for i in range(len(good)):
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(bad)
                self.assertEqual(str(cm.exception),
                    'bad content-length: {!r}'.format(bad)
                )

        good_values = (
            b'0',
            b'1',
            b'9',
            b'11',
            b'99',
            b'1111111111111111',
            b'9007199254740992',
            b'9999999999999999',
        )
        for good in good_values:
            self.assertEqual(parse_content_length(good), int(good))
            self.assertEqual(str(int(good)).encode(), good)
            for bad in iter_bad(good, b'0123456789'):
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(bad)
                self.assertEqual(str(cm.exception),
                    'bad content-length: {!r}'.format(bad)
                )
        for good in (b'1', b'9', b'11', b'99', b'10', b'90'):
            for also_good in iter_good(good, b'123456789'):
                self.assertEqual(
                    parse_content_length(also_good),
                    int(also_good)
                )

        # Remaining tests only apply to C backend
        if self.backend is not _base:
            return

        # Compare C to Python implementations with the same random values:
        functions = (_base.parse_content_length, _basepy.parse_content_length)
        for i in range(1000):
            bad = os.urandom(16)
            for func in functions:
                exc = 'bad content-length: {!r}'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception), exc, func.__module__)
            bad2 = bad + b'1'
            for func in functions:
                exc = 'content-length too long: {!r}...'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad2)
                self.assertEqual(str(cm.exception), exc, func.__module__)
        for i in range(5000):
            goodval = random.randint(0, 9999999999999999)
            good = str(goodval).encode()
            for func in functions:
                ret = func(good)
                self.assertIsInstance(ret, int)
                self.assertEqual(ret, goodval)

    def test_parse_range(self):
        parse_range = self.getattr('parse_range')
        Range = self.getattr('Range')

        prefix = b'bytes='
        ranges = (
            (0, 1),
            (0, 2),
            (9, 10),
            (9, 11),
            (0, 9999999999999999),
            (9999999999999998, 9999999999999999),
        )
        for (start, stop) in ranges:
            value = 'bytes={}-{}'.format(start, stop - 1)
            suffix = '{}-{}'.format(start, stop - 1).encode()
            r = parse_range(value.encode())
            self.assertIs(type(r), Range)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(r, value)

            for i in range(len(prefix)):
                g = prefix[i]
                bad = bytearray(prefix)
                for b in range(256):
                    bad[i] = b
                    src = bytes(bad) + suffix
                    if g == b:
                        r = parse_range(src)
                        self.assertIs(type(r), Range)
                        self.assertEqual(r.start, start)
                        self.assertEqual(r.stop, stop)
                        self.assertEqual(r, value)
                    else:
                        with self.assertRaises(ValueError) as cm:
                            parse_range(src)
                        self.assertEqual(str(cm.exception),
                            'bad range: {!r}'.format(src)
                        )

            b_start = str(start).encode()
            b_end = str(stop - 1).encode()
            for b in range(256):
                sep = bytes([b])
                src = prefix + b_start + sep + b_end
                if sep == b'-':
                    r = parse_range(src)
                    self.assertIs(type(r), Range)
                    self.assertEqual(r.start, start)
                    self.assertEqual(r.stop, stop)
                    self.assertEqual(r, value)
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_range(src)
                    self.assertEqual(str(cm.exception),
                        'bad range: {!r}'.format(src)
                    )

        # end < start
        for i in range(500):
            stop = random.randrange(1, MAX_LENGTH + 1)
            start = stop - 1
            good = 'bytes={}-{}'.format(start, stop - 1).encode()
            r = parse_range(good)
            self.assertIs(type(r), Range)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(str(r), good.decode())
            self.assertEqual(r, Range(start, stop))
            bad = 'bytes={}-{}'.format(start, stop - 2).encode()
            with self.assertRaises(ValueError) as cm:
                parse_range(bad)
            self.assertEqual(str(cm.exception), 'bad range: {!r}'.format(bad))

        # end > (MAX_LENGTH - 1)
        stop = MAX_LENGTH
        start = stop - 1
        good = 'bytes={}-{}'.format(start, stop - 1).encode()
        r = parse_range(good)
        self.assertIs(type(r), Range)
        self.assertEqual(r.start, start)
        self.assertEqual(r.stop, stop)
        self.assertEqual(str(r), good.decode())
        self.assertEqual(r, Range(start, stop))
        self.assertEqual(r, 'bytes=9999999999999998-9999999999999998')
        bad = 'bytes={}-{}'.format(start, stop).encode()
        with self.assertRaises(ValueError) as cm:
            parse_range(bad)
        self.assertEqual(str(cm.exception), 'bad range: {!r}'.format(bad))

        # Too long:
        for b in range(256):
            bad = good + bytes([b])
            with self.assertRaises(ValueError) as cm:
                parse_range(bad)
            self.assertEqual(str(cm.exception),
                'range too long: {!r}...'.format(good)
            )

    def test_parse_content_range(self):
        parse_content_range = self.getattr('parse_content_range')
        ContentRange = self.getattr('ContentRange')

        prefix = b'bytes '
        triplets = (
            (0, 1, 1),
            (0, 1, 2),
            (17, 18, 19),
            (0, 1, MAX_LENGTH),
            (0, MAX_LENGTH, MAX_LENGTH),
            (MAX_LENGTH - 1, MAX_LENGTH, MAX_LENGTH),
        )
        for (start, stop, total) in triplets:
            suffix = '{}-{}/{}'.format(start, stop - 1, total).encode()
            src = prefix + suffix
            cr = parse_content_range(src)
            self.assertIs(type(cr), ContentRange)
            self.assertEqual(cr.start, start)
            self.assertEqual(cr.stop, stop)
            self.assertEqual(cr.total, total)
            self.assertEqual(cr, ContentRange(start, stop, total))
            for i in range(len(prefix)):
                g = prefix[i]
                bad = bytearray(prefix)
                for b in range(256):
                    bad[i] = b
                    src = bytes(bad) + suffix
                    if g == b:
                        cr = parse_content_range(src)
                        self.assertIs(type(cr), ContentRange)
                        self.assertEqual(cr.start, start)
                        self.assertEqual(cr.stop, stop)
                        self.assertEqual(cr.total, total)
                        self.assertEqual(cr, ContentRange(start, stop, total))
                    else:
                        with self.assertRaises(ValueError) as cm:
                            parse_content_range(src)
                        self.assertEqual(str(cm.exception),
                            'bad content-range: {!r}'.format(src)
                        )

            l1 = str(start).encode()
            l2 = str(stop - 1).encode()
            l3 = str(total).encode()
            for b in range(256):
                sep = bytes([b])

                src = prefix + l1 + sep + l2 + b'/' + l3
                if sep == b'-':
                    cr = parse_content_range(src)
                    self.assertIs(type(cr), ContentRange)
                    self.assertEqual(cr.start, start)
                    self.assertEqual(cr.stop, stop)
                    self.assertEqual(cr.total, total)
                    self.assertEqual(cr, ContentRange(start, stop, total))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_content_range(src)
                    self.assertEqual(str(cm.exception),
                        'bad content-range: {!r}'.format(src)
                    )

                src = prefix + l1 + b'-' + l2 + sep + l3
                if sep == b'/':
                    cr = parse_content_range(src)
                    self.assertIs(type(cr), ContentRange)
                    self.assertEqual(cr.start, start)
                    self.assertEqual(cr.stop, stop)
                    self.assertEqual(cr.total, total)
                    self.assertEqual(cr, ContentRange(start, stop, total))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_content_range(src)
                    self.assertEqual(str(cm.exception),
                        'bad content-range: {!r}'.format(src)
                    )

        # end < start
        for i in range(500):
            total = stop = random.randrange(1, MAX_LENGTH + 1)
            start = stop - 1
            good = 'bytes {}-{}/{}'.format(start, stop - 1, total).encode()
            cr = parse_content_range(good)
            self.assertIs(type(cr), ContentRange)
            self.assertEqual(cr.start, start)
            self.assertEqual(cr.stop, stop)
            self.assertEqual(cr.total, total)
            self.assertEqual(cr, ContentRange(start, stop, total))
            bad = 'bytes {}-{}/{}'.format(start, stop - 2, total).encode()
            with self.assertRaises(ValueError) as cm:
                parse_content_range(bad)
            self.assertEqual(str(cm.exception),
                'bad content-range: {!r}'.format(bad)
            )

        # end > (MAX_LENGTH - 1)
        total = stop = MAX_LENGTH
        start = stop - 1
        good = 'bytes {}-{}/{}'.format(start, stop - 1, total).encode()
        cr = parse_content_range(good)
        self.assertIs(type(cr), ContentRange)
        self.assertEqual(cr.start, start)
        self.assertEqual(cr.stop, stop)
        self.assertEqual(cr.total, total)
        self.assertEqual(cr, ContentRange(start, stop, total))
        bad = 'bytes {}-{}/{}'.format(start, stop, total).encode()
        with self.assertRaises(ValueError) as cm:
            parse_content_range(bad)
        self.assertEqual(str(cm.exception),
            'bad content-range: {!r}'.format(bad)
        )

        # Too long:
        for b in range(256):
            bad = good + bytes([b])
            with self.assertRaises(ValueError) as cm:
                parse_content_range(bad)
            self.assertEqual(str(cm.exception),
                'content-range too long: {!r}...'.format(good)
            )

    def test_parse_headers(self):
        parse_headers = self.getattr('parse_headers')
        Range = self.getattr('Range')
        ContentRange = self.getattr('ContentRange')

        # bad *isresponse* type:
        for bad in (-1, 0, 1, None):
            with self.assertRaises(TypeError) as cm:
                parse_headers(b'Foo: bar\r\n', bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('isresponse', bool, type(bad), bad)
            )

        self.assertEqual(parse_headers(b''), {})
        self.assertEqual(parse_headers(b'K: V'), {'k': 'V'})
        with self.assertRaises(ValueError) as cm:
            parse_headers(b': V')
        self.assertEqual(str(cm.exception), "header line too short: b': V'")
        with self.assertRaises(ValueError) as cm:
            parse_headers(b': VV')
        self.assertEqual(str(cm.exception), 'header name is empty')
        with self.assertRaises(ValueError) as cm:
            parse_headers(b'K: ')
        self.assertEqual(str(cm.exception), "header line too short: b'K: '")
        with self.assertRaises(ValueError) as cm:
            parse_headers(b'KK: ')
        self.assertEqual(str(cm.exception), 'header value is empty')

        length =  b'Content-Length: 17'
        encoding = b'Transfer-Encoding: chunked'
        _range = b'Range: bytes=16-16'
        _type = b'Content-Type: text/plain'
        self.assertEqual(parse_headers(length),
            {'content-length': 17}
        )
        self.assertEqual(parse_headers(encoding),
            {'transfer-encoding': 'chunked'}
        )
        self.assertEqual(parse_headers(_type),
            {'content-type': 'text/plain'}
        )
        self.assertEqual(parse_headers(b'\r\n'.join([_type, length])),
            {'content-type': 'text/plain', 'content-length': 17}
        )
        self.assertEqual(parse_headers(b'\r\n'.join([_type, encoding])),
            {'content-type': 'text/plain', 'transfer-encoding': 'chunked'}
        )

        h = parse_headers(_range)
        self.assertEqual(h, {'range': 'bytes=16-16'})
        self.assertIs(type(h['range']), Range)
        self.assertEqual(h['range'].start, 16)
        self.assertEqual(h['range'].stop, 17)
        self.assertEqual(repr(h['range']), 'Range(16, 17)')
        self.assertEqual(str(h['range']), 'bytes=16-16')
        with self.assertRaises(ValueError) as cm:
            parse_headers(_range, isresponse=True)
        self.assertEqual(str(cm.exception),
            "response cannot include a 'range' header"
        )

        _content_range = b'Content-Range: bytes 16-16/23'
        h = parse_headers(_content_range, isresponse=True)
        self.assertEqual(set(h), {'content-range'})
        cr = h['content-range']
        self.assertIs(type(cr), ContentRange)
        self.assertEqual(cr, 'bytes 16-16/23')
        self.assertEqual(cr.start, 16)
        self.assertEqual(cr.stop, 17)
        self.assertEqual(cr.total, 23)
        self.assertEqual(repr(cr), 'ContentRange(16, 17, 23)')
        self.assertEqual(str(cr), 'bytes 16-16/23')
        with self.assertRaises(ValueError) as cm:
            parse_headers(_content_range)
        self.assertEqual(str(cm.exception),
            "request cannot include a 'content-range' header"
        )

        badsrc = b'\r\n'.join([length, encoding])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        badsrc = b'\r\n'.join([length, _range])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot include range header and content-length/transfer-encoding'
        )
        badsrc = b'\r\n'.join([encoding, _range])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot include range header and content-length/transfer-encoding'
        )

        key = b'Content-Length'
        val = b'17'
        self.assertEqual(len(SEP_PERMUTATIONS), 514)
        good_count = 0
        for sep in SEP_PERMUTATIONS:
            line = b''.join([key, sep, val])
            if sep == b': ':
                good_count += 1
                self.assertEqual(parse_headers(line), {'content-length': 17})
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_headers(line)
                self.assertEqual(str(cm.exception),
                    'bad header line: {!r}'.format(line)
                )
        self.assertEqual(good_count, 2)

        self.assertEqual(len(CRLF_PERMUTATIONS), 514)
        good_count = 0
        for crlf in CRLF_PERMUTATIONS:
            src1 = b''.join([length, crlf, _type])
            src2 = b''.join([_type, crlf, length])
            if crlf == b'\r\n':
                good_count += 1
                self.assertEqual(parse_headers(src1),
                    {'content-type': 'text/plain', 'content-length': 17}
                )
                self.assertEqual(parse_headers(src2),
                    {'content-type': 'text/plain', 'content-length': 17}
                )
            else:
                badval1 = b''.join([b'17', crlf, _type])
                with self.assertRaises(ValueError) as cm:
                    parse_headers(src1)
                self.assertEqual(str(cm.exception),
                    'content-length too long: {!r}...'.format(badval1[:16])
                )
                badval2 = b''.join([b'text/plain', crlf, length])
                with self.assertRaises(ValueError) as cm:
                    parse_headers(src2)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header value: {!r}'.format(badval2)
                )
        self.assertEqual(good_count, 2)

    def test_parse_request(self):
        api = self.api
        parse_request = self.getattr('parse_request')
        EmptyPreambleError = self.getattr('EmptyPreambleError')
        Request = self.getattr('Request')
        Range = self.getattr('Range')
        rfile = io.BytesIO()

        with self.assertRaises(EmptyPreambleError) as cm:
            parse_request(b'', rfile)
        self.assertEqual(str(cm.exception), 'request preamble is empty')

        r = parse_request(b'GET / HTTP/1.1', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)

        r = parse_request(b'GET / HTTP/1.1\r\nRange: bytes=17-20', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertEqual(r.headers, {'range': 'bytes=17-20'})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)

        _range = r.headers['range']
        self.assertIs(type(_range), Range)
        self.assertEqual(_range.start, 17)
        self.assertEqual(_range.stop, 21)
        self.assertEqual(_range, Range(17, 21))
        self.assertEqual(_range, 'bytes=17-20')
        self.assertEqual(repr(_range), 'Range(17, 21)')
        self.assertEqual(str(_range), 'bytes=17-20')

        r = parse_request(b'GET /foo? HTTP/1.1', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo?')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo'])
        self.assertEqual(r.query, '')

        r = parse_request(b'GET /foo/bar/?stuff=junk HTTP/1.1', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo/bar/?stuff=junk')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo', 'bar', ''])
        self.assertEqual(r.query, 'stuff=junk')

        r = parse_request(b'PUT /foo HTTP/1.1', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)

        r = parse_request(b'PUT /foo HTTP/1.1\r\nContent-Length: 17', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {'content-length': 17})
        self.assertIs(type(r.body), api.Body)
        self.assertIs(r.body.rfile, rfile)
        self.assertEqual(r.body.content_length, 17)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)

        r = parse_request(b'PUT /foo HTTP/1.1\r\nTransfer-Encoding: chunked', rfile)
        self.assertIs(type(r), Request)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
        self.assertIs(type(r.body), api.ChunkedBody)
        self.assertIs(r.body.rfile, rfile)
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)

        # Make sure that 'content-length' and 'transfer-encoding' headers are
        # only allowed when the method is 'PUT' or 'POST':
        templates = (
            '{} /bar?hello HTTP/1.1\r\nContent-Length: 18',
            '{} /baz?answer=42 HTTP/1.1\r\nTransfer-Encoding: chunked',
        )
        keys = ('content-length', 'transfer-encoding')
        for method in GOOD_METHODS:
            sources = tuple(t.format(method).encode() for t in templates)
            if method in ('PUT', 'POST'):
                # With 'content-length':
                r = parse_request(sources[0], rfile)
                self.assertIs(type(r), Request)
                self.assertEqual(r.method, method)
                self.assertEqual(r.uri, '/bar?hello')
                self.assertEqual(r.headers, {'content-length': 18})
                self.assertIs(type(r.body), api.Body)
                self.assertIs(r.body.rfile, rfile)
                self.assertEqual(r.mount, [])
                self.assertEqual(r.path, ['bar'])
                self.assertEqual(r.query, 'hello')

                # With 'transfer-encoding':
                r = parse_request(sources[1], rfile)
                self.assertIs(type(r), Request)
                self.assertEqual(r.method, method)
                self.assertEqual(r.uri, '/baz?answer=42')
                self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
                self.assertIs(type(r.body), api.ChunkedBody)
                self.assertIs(r.body.rfile, rfile)
                self.assertEqual(r.mount, [])
                self.assertEqual(r.path, ['baz'])
                self.assertEqual(r.query, 'answer=42')
            else:
                for (src, key) in zip(sources, keys):
                    with self.assertRaises(ValueError) as cm:
                        parse_request(src, rfile)
                    self.assertEqual(str(cm.exception),
                        "{!r} request with a {!r} header".format(method, key)
                    )

    def test_parse_response(self):
        api = self.api
        parse_response = self.getattr('parse_response')
        EmptyPreambleError = self.getattr('EmptyPreambleError')
        ResponseType = self.getattr('ResponseType')
        rfile = io.BytesIO()

        with self.assertRaises(EmptyPreambleError) as cm:
            parse_response('GET', b'', rfile)
        self.assertEqual(str(cm.exception), 'response preamble is empty')

        for method in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:    
                parse_response(method, b'HTTP/1.1 200 OK', rfile)
            self.assertEqual(str(cm.exception),
                'bad method: {!r}'.format(method)
            )

        body_methods = ('GET', 'PUT', 'POST', 'DELETE')
        length = b'HTTP/1.1 200 OK\r\nContent-Length: 17'

        r = parse_response('HEAD', length, rfile)
        self.assertIs(type(r), ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'content-length': 17})
        self.assertIsNone(r.body)

        for method in body_methods:
            r = parse_response(method, length, rfile)
            self.assertIs(type(r), ResponseType)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.reason, 'OK')
            self.assertEqual(r.headers, {'content-length': 17})
            self.assertIs(type(r.body), api.Body)
            self.assertIs(r.body.rfile, rfile)
            self.assertEqual(r.body.content_length, 17)

        chunked = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked'

        r = parse_response('HEAD', chunked, rfile)
        self.assertIs(type(r), ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
        self.assertIsNone(r.body)

        for method in body_methods:
            r = parse_response(method, chunked, rfile)
            self.assertIs(type(r), ResponseType)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.reason, 'OK')
            self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
            self.assertIs(type(r.body), api.ChunkedBody)
            self.assertIs(r.body.rfile, rfile)

    def test_parse_chunk_size(self):
        parse_chunk_size  = self.getattr('parse_chunk_size')
        HEX = b'0123456789ABCDEFabcdef'
        for num in range(256):
            lcase = '{:x}'.format(num).encode()
            ucase = '{:X}'.format(num).encode()
            self.assertEqual(lcase, lcase.lower())
            self.assertEqual(ucase, ucase.upper())
            for src in (lcase, ucase):
                n = parse_chunk_size(src)
                self.assertIs(type(n), int)
                self.assertEqual(n, num)
                for i in range(len(src)):
                    tmp = bytearray(src)
                    for b in range(256):
                        tmp[i] = b
                        new = bytes(tmp)
                        if b in HEX and (new[0] != 48 or len(new) == 1):
                            n = parse_chunk_size(new)
                            self.assertIs(type(n), int)
                            self.assertEqual(n, int(new, 16))
                        else:
                            with self.assertRaises(ValueError) as cm:
                                parse_chunk_size(new)
                            self.assertEqual(str(cm.exception),
                                'bad chunk_size: {!r}'.format(new)
                            )

        diff = 100
        iomax = 16 * 1024 * 1024
        for num in range(iomax - diff, iomax + diff):
            src = '{:x}'.format(num).encode()
            if num > iomax:
                with self.assertRaises(ValueError) as cm:
                    parse_chunk_size(src)
                self.assertEqual(str(cm.exception),
                    'need chunk_size <= {}; got {}'.format(iomax, num)
                )
            else:
                n = parse_chunk_size(src)
                self.assertIs(type(n), int)
                self.assertEqual(n, num)

        hmax = int(b'f' * 7, 16)
        self.assertEqual(hmax, 268435455)
        self.assertEqual(len('{:x}'.format(hmax)), 7)
        self.assertEqual(len('{:x}'.format(hmax + 1)), 8)
        for num in range(hmax - diff, hmax + diff):
            src = '{:x}'.format(num).encode()
            with self.assertRaises(ValueError) as cm:
                parse_chunk_size(src)
            if num > hmax:
                self.assertEqual(str(cm.exception),
                    'chunk_size is too long: {!r}...'.format(src[:7])
                )
            else:
                self.assertEqual(str(cm.exception),
                    'need chunk_size <= {}; got {}'.format(iomax, num)
                )

    def test_parse_chunk_extension(self):
        parse_chunk_extension = self.getattr('parse_chunk_extension')
        EXTKEY = _basepy.EXTKEY
        EXTVAL = _basepy.EXTVAL
        self.assertEqual(parse_chunk_extension(b'k=v'), ('k', 'v'))
        self.assertEqual(parse_chunk_extension(b'key=value'), ('key', 'value'))

        for bad in (b'', b'k', b'kv', b'kev', b'keyvalue', b'k=', b'=v'):
            with self.assertRaises(ValueError) as cm:
                parse_chunk_extension(bad)
            self.assertEqual(str(cm.exception),
                'bad chunk extension: {!r}'.format(bad)
            )

        def random_allowed(allowed, min_len, max_len):
            assert type(allowed) is frozenset
            assert type(min_len) is int and min_len > 0
            assert type(max_len) is int and max_len > min_len
            for size in range(min_len, max_len):
                yield bytes(random.sample(allowed, size))

        keys = tuple(random_allowed(EXTKEY, 1, 16))
        vals = tuple(random_allowed(EXTVAL, 1, 16))
        for key in keys:
            k = key.decode()
            for val in vals:
                v = val.decode()
                good = key + b'=' + val
                self.assertEqual(parse_chunk_extension(good), (k, v))
                for b in range(256):
                    sep = bytes([b])
                    bad = key + sep + val
                    if b == 61:
                        self.assertEqual(bad, good)
                        continue
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(bad)
                    self.assertEqual(str(cm.exception),
                        'bad chunk extension: {!r}'.format(bad)
                    )

        ALL = frozenset(range(256))
        badkey = ALL - EXTKEY
        badval = ALL - EXTVAL
        for (key, val) in [(b'k', b'v'), (b'key', b'value')]:
            for i in range(len(key)):
                tmp = bytearray(key)
                for b in badkey:
                    tmp[i] = b
                    bad = bytes(tmp)
                    ext = b'='.join([bad, val])
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(ext)
                    if b == 61:
                        if i > 0:
                            self.assertEqual(str(cm.exception),
                                'bad chunk extension value: {!r}'.format(
                                    ext[i+1:]
                                )
                            )
                        else:
                            self.assertEqual(str(cm.exception),
                                'bad chunk extension: {!r}'.format(ext)
                            ) 
                    else:
                        self.assertEqual(str(cm.exception),
                            'bad chunk extension key: {!r}'.format(bad)
                        )
            for i in range(len(val)):
                tmp = bytearray(val)
                for b in badval:
                    tmp[i] = b
                    bad = bytes(tmp)
                    ext = b'='.join([key, bad])
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(ext)
                    self.assertEqual(str(cm.exception),
                        'bad chunk extension value: {!r}'.format(bad)
                    )

    def test_parse_chunk(self):
        parse_chunk = self.getattr('parse_chunk')
        self.assertEqual(parse_chunk(b'0'), (0, None))
        self.assertEqual(parse_chunk(b'0;k=v'), (0, ('k', 'v')))

        self.assertEqual(parse_chunk(b'1000000'), (16777216, None))
        self.assertEqual(parse_chunk(b'1000000;k=v'), (16777216, ('k', 'v')))

        with self.assertRaises(ValueError) as cm:
            parse_chunk(b'')
        self.assertEqual(str(cm.exception), "b'\\r\\n' not found in b''...")
        with self.assertRaises(ValueError) as cm:
            parse_chunk(b';k=v')
        self.assertEqual(str(cm.exception), "bad chunk_size: b''")
        with self.assertRaises(ValueError) as cm:
            parse_chunk(b'0;')
        self.assertEqual(str(cm.exception), "bad chunk extension: b''")

        tmp = bytearray(b'0;k=v')
        for b in range(256):
            tmp[1] = b
            src = bytes(tmp)
            if b == 59:
                self.assertEqual(parse_chunk(src), (0, ('k', 'v')))
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_chunk(src)
                self.assertEqual(str(cm.exception),
                    'bad chunk_size: {!r}'.format(src)
                )

class TestParsingFunctions_C(TestParsingFunctions_Py):
    backend = _base


class TestMiscFunctions_Py(BackendTestCase):
    def test_readchunk(self):
        readchunk  = self.getattr('readchunk')
 
        # rfile.readline missing:
        class MissingReadline:
            def readinto(self, buf):
                assert False
        rfile = MissingReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingReadline' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.readline() not callable:
        class BadReadline:
            readline = 'hello'
            def readinto(self, buf):
                assert False
        rfile = BadReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.readinto missing:
        class MissingRead:
            def readline(self, size):
                assert False
        rfile = MissingRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingRead' object has no attribute 'readinto'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.readinto() not callable:
        class BadRead:
            readinto = 'hello'
            def readline(self, size):
                assert False
        rfile = BadRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readinto() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'0\r\n\r\n')
        self.assertEqual(readchunk(rfile), (None, b''))
        self.assertEqual(sys.getrefcount(rfile), 2)
        rfile = io.BytesIO(b'0;key=value\r\n\r\n')
        self.assertEqual(readchunk(rfile), (('key', 'value'), b''))
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c\r\nhello, world\r\n')
        self.assertEqual(readchunk(rfile), (None, b'hello, world'))
        self.assertEqual(sys.getrefcount(rfile), 2)
        rfile = io.BytesIO(b'c;key=value\r\nhello, world\r\n')
        self.assertEqual(readchunk(rfile), (('key', 'value'), b'hello, world'))
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() dosen't return bytes:
        class Bad1:
            def readline(self, size):
                assert type(size) is int and size == 4096
                return bytearray(b'c\r\n')
            def readinto(self, buf):
                assert False
        rfile = Bad1()
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            'need a {!r}; readline() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # what readline() returns doesn't contain a b'\r\n':
        class Bad2:
            def __init__(self, line):
                self.__line = line
            def readline(self, size):
                assert type(size) is int and size == 4096
                return self.__line
            def readinto(self, buf):
                assert False
        for bad in (b'', b'\n', b'c', b'c\rhello, world', b'c\nhello, world'):
            rfile = Bad2(bad)
            with self.assertRaises(ValueError) as cm:
                readchunk(rfile)
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad)
            )
            self.assertEqual(sys.getrefcount(rfile), 2)

        # readinto() dosen't return an int:
        class Bad3:
            def __init__(self, data):
                self.__data = data
            def readline(self, size):
                assert type(size) is int and size == 4096
                return b'c\r\n'
            def readinto(self, buf):
                assert type(buf) is memoryview and len(buf) == 14
                buf[0:14] = self.__data
                return 14.0

        ret = bytearray(b'hello, world\r\n')
        self.assertEqual(len(ret), 14)
        rfile = Bad3(ret)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('received', int, float, 14.0)
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readinto() doesn't return the correct amount of data:
        class Bad4:
            def __init__(self, data):
                self.__data = list(data)
            def readline(self, size):
                assert type(size) is int and size == 4096
                return b'c\r\n'
            def readinto(self, buf):
                assert type(buf) is memoryview and len(buf) > 0
                if len(self.__data) == 0:
                    return 0
                buf[0] = self.__data.pop(0)
                return 1

        for bad in (b'', b'hello world\r\n'):
            rfile = Bad4(bad)
            with self.assertRaises(ValueError) as cm:
                readchunk(rfile)
            self.assertEqual(str(cm.exception),
                'expected to read 14 bytes, but received {}'.format(len(bad))
            ) 
            self.assertEqual(sys.getrefcount(rfile), 2)

    def test_write_chunk(self):
        write_chunk  = self.getattr('write_chunk')

        def getrefcounts(wfile, chunk):
            counts = {
                'wfile': sys.getrefcount(wfile),
                'chunk': sys.getrefcount(chunk),
                'chunk[0]': sys.getrefcount(chunk[0]),
                'chunk[1]': sys.getrefcount(chunk[1]),
            }
            if chunk[0] is not None:
                counts['chunk[0][0]'] = sys.getrefcount(chunk[0][0])
                counts['chunk[0][1]'] = sys.getrefcount(chunk[0][1])
            return counts

        wfile = io.BytesIO()
        chunk = (None, b'')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 5)
        self.assertEqual(wfile.getvalue(), b'0\r\n\r\n')
        if sys.version_info < (3, 5):
            # FIXME: Why does this fail on Python 3.5?
            self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (('k', 'v'), b'')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 9)
        self.assertEqual(wfile.getvalue(), b'0;k=v\r\n\r\n')
        if sys.version_info < (3, 5):
            # FIXME: Why does this fail on Python 3.5?
            self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (None, b'hello, world')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 17)
        self.assertEqual(wfile.getvalue(), b'c\r\nhello, world\r\n')
        if sys.version_info < (3, 5):
            # FIXME: Why does this fail on Python 3.5?
            self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (('k', 'v'), b'hello, world')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 21)
        self.assertEqual(wfile.getvalue(), b'c;k=v\r\nhello, world\r\n')
        if sys.version_info < (3, 5):
            # FIXME: Why does this fail on Python 3.5?
            self.assertEqual(getrefcounts(wfile, chunk), counts)

    def test_set_output_headers(self):
        set_output_headers = self.getattr('set_output_headers')
        api = self.api

        # None:
        h = {}
        self.assertIsNone(set_output_headers(h, None))
        self.assertEqual(h, {})

        # bytes:
        h = {}
        self.assertIsNone(set_output_headers(h, b''))
        self.assertEqual(h, {'content-length': 0})
        h = {}
        self.assertIsNone(set_output_headers(h, os.urandom(17)))
        self.assertEqual(h, {'content-length': 17})

        # api.Body:
        h = {}
        body = api.Body(io.BytesIO(), 0)
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'content-length': 0})
        h = {}
        body = api.Body(io.BytesIO(), 17)
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'content-length': 17})

        # api.ChunkedBody:
        h = {}
        body = api.ChunkedBody(io.BytesIO())
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'transfer-encoding': 'chunked'})

        # api.BodyIter:
        h = {}
        body = api.BodyIter([], 0)
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'content-length': 0})
        h = {}
        body = api.BodyIter([], 17)
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'content-length': 17})

        # api.ChunkedBodyIter:
        h = {}
        body = api.ChunkedBodyIter([])
        self.assertIsNone(set_output_headers(h, body))
        self.assertEqual(h, {'transfer-encoding': 'chunked'})

        # Test some bad body types:
        for bad in ('hello', bytearray(b'hello')):
            h = {}
            with self.assertRaises(TypeError) as cm:
                set_output_headers(h, bad)
            self.assertEqual(str(cm.exception),
                'bad body type: {!r}: {!r}'.format(type(bad), bad)
            )
            self.assertEqual(h, {})

        # Test when header is already set and matches:
        def iter_matching():
            yield ({'content-length': 0}, b'')
            yield ({'content-length': 17}, os.urandom(17))

            yield ({'content-length': 0}, api.Body(io.BytesIO(), 0))
            yield ({'content-length': 17}, api.Body(io.BytesIO(), 17))
    
            yield ({'content-length': 0}, api.BodyIter([], 0))
            yield ({'content-length': 17}, api.BodyIter([], 17))

            yield (
                {'transfer-encoding': 'chunked'},
                api.ChunkedBody(io.BytesIO())
            )

            yield ({'transfer-encoding': 'chunked'}, api.ChunkedBodyIter([]))

        for (h, body) in iter_matching():
            hcopy = h.copy()
            self.assertIsNone(set_output_headers(hcopy, body))
            self.assertEqual(hcopy, h)

        # Test when header is already set and and does *not* match:
        def iter_not_matching():
            yield ({'content-length': 1}, b'')
            yield ({'content-length': 0}, os.urandom(1))
            yield ({'content-length': 16}, os.urandom(17))
            yield ({'content-length': 18}, os.urandom(17))

            yield ({'content-length': 1}, api.Body(io.BytesIO(), 0))
            yield ({'content-length': 0}, api.Body(io.BytesIO(), 1))
            yield ({'content-length': 16}, api.Body(io.BytesIO(), 17))
            yield ({'content-length': 18}, api.Body(io.BytesIO(), 17))
    
            yield ({'content-length': 1}, api.BodyIter([], 0))
            yield ({'content-length': 0}, api.BodyIter([], 1))
            yield ({'content-length': 16}, api.BodyIter([], 17))
            yield ({'content-length': 18}, api.BodyIter([], 17))

            yield (
                {'transfer-encoding': 'clumped'},
                api.ChunkedBody(io.BytesIO())
            )
            yield (
                {'transfer-encoding': 'chunke'},
                api.ChunkedBody(io.BytesIO())
            )
            yield (
                {'transfer-encoding': 'chunkedy'},
                api.ChunkedBody(io.BytesIO())
            )

            yield ({'transfer-encoding': 'clumped'}, api.ChunkedBodyIter([]))
            yield ({'transfer-encoding': 'chunke'}, api.ChunkedBodyIter([]))
            yield ({'transfer-encoding': 'chunkedy'}, api.ChunkedBodyIter([]))

        for (h, body) in iter_not_matching():
            hcopy = h.copy()
            items = tuple(h.items())
            self.assertEqual(len(items), 1)
            (key, val) = items[0]
            if type(body) is bytes:
                newval = len(body)
            elif type(body) in (api.Body, api.BodyIter):
                newval = body.content_length
            elif type(body) in (api.ChunkedBody, api.ChunkedBodyIter):
                newval = 'chunked'
            else:
                raise Exception('should not be reached')
            with self.assertRaises(ValueError) as cm:
                set_output_headers(hcopy, body)
            self.assertEqual(str(cm.exception),
                '{!r} mismatch: {!r} != {!r}'.format(key, newval, val)
            )
            self.assertEqual(hcopy, h)


class TestMiscFunctions_C(TestMiscFunctions_Py):
    backend = _base


class dict_subclass(dict):
    pass

class str_subclass(str):
    pass

class int_subclass(int):
    pass


class FormatHeaders_Py:
    def __init__(self, func):
        self._func = func

    def __call__(self, headers):
        return self._func(headers).encode('latin_1')


class FormatHeaders_C:
    def __init__(self, func):
        self._func = func
        self._dst = memoryview(bytearray(4096))

    def __call__(self, headers):
        stop = self._func(self._dst, headers)
        return self._dst[0:stop].tobytes()


class TestFormatting_Py(BackendTestCase):
    def test_set_default_header(self):
        set_default_header = self.getattr('set_default_header')

        # key not yet present:
        headers = {}
        key = random_id().lower()
        rawval = random_id(20)
        val1 = rawval[:24]
        self.assertEqual(sys.getrefcount(key), 2)
        self.assertEqual(sys.getrefcount(val1), 2)
        self.assertIsNone(set_default_header(headers, key, val1))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)

        # same val instance:
        self.assertIsNone(set_default_header(headers, key, val1))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)

        # equal val but different val instance:
        val2 = rawval[:24]
        self.assertIsNot(val2, val1)
        self.assertEqual(val2, val1)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertIsNone(set_default_header(headers, key, val2))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)
        self.assertEqual(sys.getrefcount(val2), 2)

        # non-equal val:
        val3 = random_id()
        self.assertNotEqual(val3, val2)
        self.assertEqual(sys.getrefcount(val3), 2)
        with self.assertRaises(ValueError) as cm:
            set_default_header(headers, key, val3)
        self.assertEqual(str(cm.exception),
            '{!r} mismatch: {!r} != {!r}'.format(key, val3, val1)
        )
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertEqual(sys.getrefcount(val3), 2)

        # delete headers:
        del headers
        self.assertEqual(sys.getrefcount(key), 2)
        self.assertEqual(sys.getrefcount(val1), 2)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertEqual(sys.getrefcount(val3), 2)

    def check_render(self, expected, func, *args):
        size = len(expected)

        # Test when dst has exactly enough space:
        dst = memoryview(bytearray(size))
        stop = func(dst, *args)
        self.assertIs(type(stop), int)
        self.assertEqual(stop, size)
        self.assertEqual(dst.tobytes(), expected)

        # Test when dst has extra space:
        dst = memoryview(bytearray(size + 100))
        stop = func(dst, *args)
        self.assertIs(type(stop), int)
        self.assertEqual(stop, size)
        self.assertEqual(dst[:size].tobytes(), expected)
        self.assertEqual(dst[size:], b'\x00' * 100)

        # Test when len(dst) is from zero to size - 1:
        for toosmall in range(size):
            dst = memoryview(bytearray(toosmall))
            with self.assertRaises(ValueError) as cm:
                func(dst, *args)
            self.assertEqual(str(cm.exception),
                'output size exceeds {}'.format(toosmall)
            )

    def check_render_headers(self, headers):
        expected = ''.join(
            '\r\n{}: {}'.format(k, headers[k])
            for k in sorted(headers) 
        ).encode('ascii')
        func = self.getattr('render_headers')
        self.check_render(expected, func, headers)
        return expected

    def test_render_headers(self):
        render_headers = self.getattr('render_headers')
        Range = self.getattr('Range')
        ContentRange = self.getattr('ContentRange')

        dst = memoryview(bytearray(4096))
        empty = dst.tobytes()

        # Bad headers type:
        bad = [('foo', 'bar')]
        with self.assertRaises(TypeError) as cm:
            render_headers(dst, bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, list, bad)
        )
        self.assertEqual(dst.tobytes(), empty)
        bad = dict_subclass({'foo': 'bar'})
        with self.assertRaises(TypeError) as cm:
            render_headers(dst, bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, dict_subclass, bad)
        )
        self.assertEqual(dst.tobytes(), empty)

        # Empty headers
        self.assertEqual(render_headers(dst, {}), 0)
        self.assertEqual(dst.tobytes(), empty)

        # Max number of headers:
        headers = bad = dict(
            (random_key(32), random_val(101))
            for i in range(self.MAX_HEADER_COUNT)
        )
        self.check_render_headers(headers)
        self.assertEqual(dst.tobytes(), empty)

        # Add one more:
        headers[random_key(32)] = random_val(101)
        with self.assertRaises(ValueError) as cm:
            render_headers(dst, headers)
        self.assertEqual(str(cm.exception),
            'need len(headers) <= {}; got {}'.format(
                self.MAX_HEADER_COUNT, self.MAX_HEADER_COUNT + 1
            )
        )
        self.assertEqual(dst.tobytes(), empty)

        ml = self.MAX_LENGTH
        good = {
            'content-length': ml,
            'range': Range(ml - 1, ml),
            'content-range': ContentRange(ml - 1, ml, ml),
        }
        good.update(
            (random_key(size), random_val(size))
            for size in range(1, 10)
        )
        self.check_render_headers(good)
        key = random_key(17)
        val = random_key(37)
        alsogood = good.copy()
        alsogood[key] = val
        self.check_render_headers(good)

        # bad key type:
        for bad_key in [key.encode(), str_subclass(key), tuple(key), None, 17]:
            bad = good.copy()
            bad[bad_key] = val
            with self.assertRaises(TypeError) as cm:
                render_headers(dst, bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('key', str, type(bad_key), bad_key)
            )

        # bad key value:
        for bad_key in iter_bad_keys():
            bad = good.copy()
            bad[bad_key] = val
            with self.assertRaises(ValueError) as cm:
                render_headers(dst, bad)
            self.assertEqual(str(cm.exception),
                'bad key: {!r}'.format(bad_key)
            )

        # key is too long:
        for bad_key in [random_key(33), random_key(34), random_key(101)]:
            bad = good.copy()
            bad[bad_key] = val
            with self.assertRaises(ValueError) as cm:
                render_headers(dst, bad)
            self.assertEqual(str(cm.exception),
                'key is too long: {!r}'.format(bad_key)
            )

        class ValObj:
            def __init__(self, strval):
                self.__strval = strval

            def __str__(self):
                strval = self.__strval
                if isinstance(strval, Exception):
                    raise strval
                return strval

        # val.__str__() doesn't return str:
        bad = good.copy()
        bad_val = ValObj(val.encode())
        bad[key] = bad_val
        with self.assertRaises(TypeError) as cm:
            render_headers(dst, bad)
        self.assertEqual(str(cm.exception),
            '__str__ returned non-string (type bytes)'
        )
        del bad
        self.assertEqual(sys.getrefcount(bad_val), 2)

        # val.__str__() raises an exception:
        marker = random_id(30)
        exc = ValueError(marker)
        self.assertEqual(sys.getrefcount(exc), 2)
        bad = good.copy()
        bad_val = ValObj(exc)
        bad[key] = bad_val
        with self.assertRaises(ValueError) as cm:
            render_headers(dst, bad)
        self.assertEqual(str(cm.exception), marker)
        del bad
        self.assertEqual(sys.getrefcount(bad_val), 2)
        del bad_val
        self.assertEqual(sys.getrefcount(exc), 3)

        # val has codepoints > 127
        for bad_val in ['', '¡™', STR256]:
            for valobj in [bad_val, ValObj(bad_val)]:
                bad = good.copy()
                bad[key] = bad_val
                with self.assertRaises(ValueError) as cm:
                    render_headers(dst, bad)
                self.assertEqual(str(cm.exception),
                    'bad val: {!r}'.format(bad_val)
                )

        # Test sorting corner case most likely to be problem with C backend:
        items = tuple(
            ('d' * i, random_val(10))
            for i in range(1, self.MAX_HEADER_COUNT + 1)
        )
        expected = ''.join(
            '\r\n{}: {}'.format(*kv) for kv in items
        ).encode()
        got = self.check_render_headers(dict(items))
        self.assertEqual(got, expected)

    def check_render_request(self, method, uri, headers):
        lines = ['{} {} HTTP/1.1'.format(method, uri)]
        lines.extend(
            '{}: {}'.format(k, headers[k])
            for k in sorted(headers) 
        ) 
        expected = '\r\n'.join(lines).encode() + b'\r\n\r\n'   
        func = self.getattr('render_request')
        self.check_render(expected, func, method, uri, headers)
        return expected

    def test_render_request(self):
        render_request = self.getattr('render_request')

        dst = memoryview(bytearray(4096))
        empty = dst.tobytes()

        # Bad method type:
        for method in [17, str_subclass('GET'), b'GET']:
            with self.assertRaises(TypeError) as cm:
                render_request(dst, method, '/', {})
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('method', str, type(method), method)
            )
            self.assertEqual(dst.tobytes(), empty)

        # Bad method value:
        for method in ['', '¡™', STR256]:
            with self.assertRaises(ValueError) as cm:
                render_request(dst, method, '/', {})
            self.assertEqual(str(cm.exception),
                'bad method: {!r}'.format(method)
            )
            self.assertEqual(dst.tobytes(), empty)

        # Bad uri type:
        for uri in [17, str_subclass('/foo'), b'/foo']:
            with self.assertRaises(TypeError) as cm:
                render_request(dst, 'GET', uri, {})
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('uri', str, type(uri), uri)
            )

        # Bad uri value:
        for uri in ['', '¡™', STR256]:
            with self.assertRaises(ValueError) as cm:
                render_request(dst, 'GET', uri, {})
            self.assertEqual(str(cm.exception),
                'bad uri: {!r}'.format(uri)
            )

        # Bad headers type:
        for headers in [[('foo', 'bar')], dict_subclass({'foo': 'bar'})]:
            with self.assertRaises(TypeError) as cm:
                render_request(dst, 'GET', '/', headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('headers', dict, type(headers), headers)
            )

        for method in ('GET', 'HEAD', 'PUT', 'POST', 'DELETE'):
            got = self.check_render_request(method, '/', {})
            self.assertEqual(got,
                '{} / HTTP/1.1\r\n\r\n'.format(method).encode()
            )
            got = self.check_render_request(method, '/foo?k=v', {})
            self.assertEqual(got,
                '{} /foo?k=v HTTP/1.1\r\n\r\n'.format(method).encode()
            )
            got = self.check_render_request(method, '/', {'content-type': 'text/plain'})
            self.assertEqual(got,
                '{} / HTTP/1.1\r\ncontent-type: text/plain\r\n\r\n'.format(method).encode()
            )

        # long uri
        uri = '/' + '/'.join(random_id(30) for i in range(50))
        self.check_render_request('GET', uri, {})

        # lots of headers
        headers = dict(
            (random_key(size), random_val(50))
            for size in range(1, self.MAX_HEADER_COUNT + 1)  
        )
        self.check_render_request('GET', '/', headers)
        self.check_render_request('GET', uri, headers)

    def check_render_response(self, status, reason, headers):
        lines = ['HTTP/1.1 {} {}'.format(status, reason)]
        lines.extend(
            '{}: {}'.format(k, headers[k])
            for k in sorted(headers) 
        ) 
        expected = '\r\n'.join(lines).encode() + b'\r\n\r\n' 
        func = self.getattr('render_response')  
        self.check_render(expected, func, status, reason, headers)
        return expected

    def test_render_response(self):
        render_response = self.getattr('render_response')

        dst = memoryview(bytearray(4096))
        empty = dst.tobytes()
        self.assertEqual(dst.tobytes(), empty)

        # Bad status type:
        for status in ['200', 200.0, int_subclass(200)]:
            with self.assertRaises(TypeError) as cm:
                render_response(dst, status, 'OK', {})
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('status', int, type(status), status)
            )
            self.assertEqual(dst.tobytes(), empty)

        # Bad status value:
        for status in [-1, 0, 99, 600]:
            with self.assertRaises(ValueError) as cm:
                render_response(dst, status, 'OK', {})
            self.assertEqual(str(cm.exception),
                'need 100 <= status <= 599; got {}'.format(status)
            )
            self.assertEqual(dst.tobytes(), empty)

        # Bad reason type:
        for reason in [17, str_subclass('OK'), b'OK']:
            with self.assertRaises(TypeError) as cm:
                render_response(dst, 200, reason, {})
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('reason', str, type(reason), reason)
            )

        # Bad reason value:
        for reason in ['', '¡™', STR256]:
            with self.assertRaises(ValueError) as cm:
                render_response(dst, 200, reason, {})
            self.assertEqual(str(cm.exception),
                'bad reason: {!r}'.format(reason)
            )

        # Bad headers type:
        for headers in [[('foo', 'bar')], dict_subclass({'foo': 'bar'})]:
            with self.assertRaises(TypeError) as cm:
                render_response(dst, 200, 'OK', headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('headers', dict, type(headers), headers)
            )

        for status in range(200, 600):
            got = self.check_render_response(status, 'OK', {})
            self.assertEqual(got,
                'HTTP/1.1 {} OK\r\n\r\n'.format(status).encode()
            )
            key = random_key(32)
            val = random_val(32)
            got = self.check_render_response(status, 'OK', {key: val})
            self.assertEqual(got,
                'HTTP/1.1 {} OK\r\n{}: {}\r\n\r\n'.format(status, key, val).encode()
            )

        # long reason:
        reason = ' '.join(random_id(30) for i in range(50))
        self.check_render_response(200, reason, {})

        # lots of headers:
        headers = dict(
            (random_key(size), random_val(50))
            for size in range(1, self.MAX_HEADER_COUNT + 1)  
        )
        self.check_render_response(200, 'OK', headers)
        self.check_render_response(200, reason, headers)

    def test_format_chunk(self):
        format_chunk = self.getattr('format_chunk')
        MAX_IO_SIZE = self.getattr('MAX_IO_SIZE')

        # chunk isn't a tuple:
        chunk = [None, b'']
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk: need a {!r}; got a {!r}'.format(tuple, list)
        )

        # chunk isn't a 2-tuple:
        for chunk in [tuple(), (None,), (None, b'', b'hello')]:
            with self.assertRaises(ValueError) as cm:
                format_chunk(chunk)
            self.assertEqual(str(cm.exception),
                'chunk: need a 2-tuple; got a {}-tuple'.format(len(chunk))
            )

        # chunk[0] isn't a tuple:
        chunk = (['key', 'value'], b'')
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk[0]: need a {!r}; got a {!r}'.format(tuple, list)
        )

        # chunk[0] isn't a 2-tuple:
        for ext in [tuple(), ('foo',), ('foo', 'bar', 'baz')]:
            chunk = (ext, b'')
            with self.assertRaises(ValueError) as cm:
                format_chunk(chunk)
            self.assertEqual(str(cm.exception),
                'chunk[0]: need a 2-tuple; got a {}-tuple'.format(len(ext))
            )

        # chunk[1] isn't bytes:
        chunk = (None, bytearray())
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk[1]: need a {!r}; got a {!r}'.format(bytes, bytearray)
        )

        # len(chunk[1]) > MAX_IO_SIZE:
        data = b'D' * (MAX_IO_SIZE + 1)
        chunk = (None, data)
        with self.assertRaises(ValueError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'need len(chunk[1]) <= {}; got {}'.format(MAX_IO_SIZE, len(data))
        )

        ext = ('k', 'v')
        self.assertEqual(format_chunk((None, b'')), b'0\r\n')
        self.assertEqual(format_chunk((ext, b'')), b'0;k=v\r\n')

        data = b'hello, world'
        self.assertEqual(format_chunk((None, data)), b'c\r\n')
        self.assertEqual(format_chunk((ext, data)), b'c;k=v\r\n')

        data = b'D' * (MAX_IO_SIZE)
        self.assertEqual(format_chunk((None, data)),
            '{:x}\r\n'.format(MAX_IO_SIZE).encode()  
        )
        self.assertEqual(format_chunk((ext, data)),
            '{:x};k=v\r\n'.format(MAX_IO_SIZE).encode()  
        )


class TestFormatting_C(TestFormatting_Py):
    backend = _base


class TestNamedTuples_Py(BackendTestCase):
    def new(self, name, count):
        args = tuple(random_id() for i in range(count))
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)
        tup = self.getattr(name)(*args)
        self.assertIsInstance(tup, tuple)
        self.assertIsInstance(tup, self.getattr(name + 'Type'))
        self.assertEqual(tup, args)
        self.assertEqual(len(tup), count)
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        return (tup, args)

    def test_API(self):
        (tup, args) = self.new('API', 6)
        self.assertIs(tup.Body,            args[0])
        self.assertIs(tup.ChunkedBody,     args[1])
        self.assertIs(tup.BodyIter,        args[2])
        self.assertIs(tup.ChunkedBodyIter, args[3])
        self.assertIs(tup.Range,           args[4])
        self.assertIs(tup.ContentRange,    args[5])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)

    def test_Response(self):
        (tup, args) = self.new('Response', 4)
        self.assertIs(tup.status,  args[0])
        self.assertIs(tup.reason,  args[1])
        self.assertIs(tup.headers, args[2])
        self.assertIs(tup.body,    args[3])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)


class TestNamedTuples_C(TestNamedTuples_Py):
    backend = _base


class TestConstants_Py(BackendTestCase):
    def test_BUF_LEN(self):
        self.assertIs(type(self.BUF_LEN), int)
        self.assertEqual(self.BUF_LEN, 32 * 1024)

    def test_SCRATCH_LEN(self):
        self.assertIs(type(self.SCRATCH_LEN), int)
        self.assertEqual(self.SCRATCH_LEN, 32)

    def test_MAX_LINE_LEN(self):
        self.assertIs(type(self.MAX_LINE_LEN), int)
        self.assertEqual(self.MAX_LINE_LEN, 4096)
        self.assertLess(self.MAX_LINE_LEN, self.BUF_LEN)

    def test_MAX_CL_LEN(self):
        self.assertIs(type(self.MAX_CL_LEN), int)
        self.assertEqual(self.MAX_CL_LEN, 16)

    def test_MAX_LENGTH(self):
        self.assertIs(type(self.MAX_LENGTH), int)
        self.assertEqual(self.MAX_LENGTH, 9999999999999999)
        self.assertEqual(self.MAX_LENGTH, int('9' * self.MAX_CL_LEN))

    def test_MAX_HEADER_COUNT(self):
        self.assertIs(type(self.MAX_HEADER_COUNT), int)
        self.assertEqual(self.MAX_HEADER_COUNT, 20)

    def test_IO_SIZE(self):
        self.assertIs(type(self.IO_SIZE), int)
        self.assertEqual(self.IO_SIZE, 1024 * 1024)
        self.assertLess(self.IO_SIZE, self.MAX_IO_SIZE)

    def test_MAX_IO_SIZE(self):
        self.assertIs(type(self.MAX_IO_SIZE), int)
        self.assertEqual(self.MAX_IO_SIZE, 16 * 1024 * 1024)

    def test_api(self):
        api = self.api
        APIType = self.getattr('APIType')

        self.assertIsInstance(api, tuple)
        self.assertIsInstance(api, APIType)

        self.assertIs(api.Body, self.backend.Body)
        self.assertIs(api.BodyIter, self.backend.BodyIter)
        self.assertIs(api.ChunkedBody, self.backend.ChunkedBody)
        self.assertIs(api.ChunkedBodyIter, self.backend.ChunkedBodyIter)
        self.assertIs(api.Range, self.backend.Range)
        self.assertIs(api.ContentRange, self.backend.ContentRange)

        self.assertIs(api[0], self.backend.Body)
        self.assertIs(api[1], self.backend.ChunkedBody)
        self.assertIs(api[2], self.backend.BodyIter)
        self.assertIs(api[3], self.backend.ChunkedBodyIter)
        self.assertIs(api[4], self.backend.Range)
        self.assertIs(api[5], self.backend.ContentRange)

        self.assertEqual(api,
            (
                self.backend.Body,
                self.backend.ChunkedBody,
                self.backend.BodyIter,
                self.backend.ChunkedBodyIter,
                self.backend.Range,
                self.backend.ContentRange,
            )
        )

class TestConstants_C(TestConstants_Py):
    backend = _base


class TestEmptyPreambleError(TestCase):
    def test_init(self):
        e = base.EmptyPreambleError('stuff and junk')
        self.assertIsInstance(e, Exception)
        self.assertIsInstance(e, ConnectionError)
        self.assertIs(type(e), base.EmptyPreambleError)
        self.assertEqual(str(e), 'stuff and junk')


class TestFunctions_Py(BackendTestCase):
    def test_parse_method(self):
        parse_method = self.getattr('parse_method')

        self.assertEqual(parse_method(b'GET'),    ('GET',     1))
        self.assertEqual(parse_method(b'PUT'),    ('PUT',     2))
        self.assertEqual(parse_method(b'POST'),   ('POST',    4))
        self.assertEqual(parse_method(b'HEAD'),   ('HEAD',    8))
        self.assertEqual(parse_method(b'DELETE'), ('DELETE', 16))

        for (i, method) in enumerate(GOOD_METHODS):
            # Input is str:
            result = parse_method(method)
            self.assertIs(type(result),  tuple)
            self.assertEqual(result, (method, 1 << i))
            self.assertIs(parse_method(method)[0], result[0])

            # Input is bytes:
            result = parse_method(method.encode())
            self.assertIs(type(result),  tuple)
            self.assertEqual(result, (method, 1 << i))
            self.assertIs(parse_method(method)[0], result[0])

            # Lowercase str:
            with self.assertRaises(ValueError) as cm:
                parse_method(method.lower())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

            # Lowercase bytes:
            with self.assertRaises(ValueError) as cm:
                parse_method(method.lower().encode())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

        # Pre-generated bad method permutations:
        for bad in BAD_METHODS_BYTES:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad)
            )

        # Random bad bytes:
        for size in range(1, 20):
            for i in range(100):
                bad = os.urandom(size)
                with self.assertRaises(ValueError) as cm:
                    parse_method(bad)
                self.assertEqual(str(cm.exception),
                    'bad HTTP method: {!r}'.format(bad)
                )

    def test_parse_uri(self):
        parse_uri = self.getattr('parse_uri')

        # Empty b'':
        with self.assertRaises(ValueError) as cm:
            parse_uri(b'')
        self.assertEqual(str(cm.exception), 'uri is empty')

        # URI does not start with /:
        with self.assertRaises(ValueError) as cm:
            parse_uri(b'foo')
        self.assertEqual(str(cm.exception), "path[0:1] != b'/': b'foo'")

        # Empty path component:
        double_slashers = (
            b'//',
            b'//foo',
            b'//foo/',
            b'//foo/bar',
            b'//foo/bar/',
            b'/foo//',
            b'/foo//bar',
            b'/foo//bar/',
            b'/foo/bar//',
        )
        for bad in double_slashers:
            for suffix in (b'', b'?', b'?q'):
                with self.assertRaises(ValueError) as cm:
                    parse_uri(bad + suffix)
                self.assertEqual(str(cm.exception),
                    "b'//' in path: {!r}".format(bad)
                )

        ret = parse_uri(b'/')
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 4)
        self.assertEqual(ret, ('/', [], [] , None))
        self.assertEqual(sys.getrefcount(ret[1]), 2)
        self.assertEqual(sys.getrefcount(ret[2]), 2)

        self.assertEqual(parse_uri(b'/'), ('/', [], [] , None))
        self.assertEqual(parse_uri(b'/?'), ('/?', [], [] , ''))
        self.assertEqual(parse_uri(b'/?q'), ('/?q', [], [] , 'q'))

        self.assertEqual(parse_uri(b'/foo'), ('/foo', [], ['foo'], None))
        self.assertEqual(parse_uri(b'/foo?'), ('/foo?', [], ['foo'], ''))
        self.assertEqual(parse_uri(b'/foo?q'), ('/foo?q', [], ['foo'], 'q'))

        self.assertEqual(parse_uri(b'/foo/'), ('/foo/', [], ['foo', ''], None))
        self.assertEqual(parse_uri(b'/foo/?'), ('/foo/?', [], ['foo', ''], ''))
        self.assertEqual(parse_uri(b'/foo/?q'),
            ('/foo/?q', [], ['foo', ''], 'q')
        )

        self.assertEqual(parse_uri(b'/foo/bar'),
            ('/foo/bar', [], ['foo', 'bar'], None)
        )
        self.assertEqual(parse_uri(b'/foo/bar?'),
             ('/foo/bar?', [], ['foo', 'bar'], '')
        )
        self.assertEqual(parse_uri(b'/foo/bar?q'),
             ('/foo/bar?q', [], ['foo', 'bar'], 'q')
        )
        self.assertEqual(parse_uri(b'/~novacut/+archive/ubuntu/daily'),
            (
                '/~novacut/+archive/ubuntu/daily',
                [],
                ['~novacut', '+archive', 'ubuntu', 'daily'],
                None
            )
        )

    def test_parse_header_name(self):
        parse_header_name = self.getattr('parse_header_name')

        # Empty bytes:
        with self.assertRaises(ValueError) as cm:
            parse_header_name(b'')
        self.assertEqual(str(cm.exception), 'header name is empty')

        # Too long:
        good = b'R' * 32
        bad =  good + b'Q'
        self.assertEqual(parse_header_name(good), good.decode().lower())
        with self.assertRaises(ValueError) as cm:
            parse_header_name(bad)
        self.assertEqual(str(cm.exception),
            'header name too long: {!r}...'.format(good)
        )

        # Too short, just right, too long:
        for size in range(69):
            buf = b'R' * size
            if 1 <= size <= 32:
                self.assertEqual(parse_header_name(buf), buf.decode().lower())
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_header_name(buf)
                if size == 0:
                    self.assertEqual(str(cm.exception), 'header name is empty')
                else:
                    self.assertEqual(str(cm.exception),
                        "header name too long: b'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'..."
                    )

        # Start with a know good value, then for each possible bad byte value,
        # copy the good value and make it bad by replacing a good byte with a
        # bad byte at each possible index:
        goodset = frozenset(
            b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        )
        badset = frozenset(range(256)) - goodset
        good = b'Super-Transfer-Encoding'
        self.assertEqual(parse_header_name(good), 'super-transfer-encoding')
        for b in badset:
            for i in range(len(good)):
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                with self.assertRaises(ValueError) as cm:
                    parse_header_name(bad)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header name: {!r}'.format(bad)
                )

    def test_parse_response_line(self):
        parse_response_line = self.getattr('parse_response_line')

        # request line is too short:
        line  = b'HTTP/1.1 200 OK'
        for stop in range(15):
            short = line[:stop]
            self.assertTrue(0 <= len(short) <= 14)
            with self.assertRaises(ValueError) as cm:
                parse_response_line(short)
            self.assertEqual(str(cm.exception),
                'response line too short: {!r}'.format(short)
            )

        # Double confirm when len(line) is 0:
        with self.assertRaises(ValueError) as cm:
            parse_response_line(b'')
        self.assertEqual(str(cm.exception),
            "response line too short: b''"
        )

        # Double confirm when len(line) is 14:
        short = line[:14]
        self.assertEqual(len(short), 14)
        with self.assertRaises(ValueError) as cm:
            parse_response_line(short)
        self.assertEqual(str(cm.exception),
            "response line too short: b'HTTP/1.1 200 O'"
        )

        # Confirm valid minimum response line is 15 bytes in length:
        self.assertEqual(len(line), 15)
        self.assertEqual(parse_response_line(line), (200, 'OK'))

        # Test all status in range 000-999, plus a few valid reasons:
        for status in range(1000):
            for reason in ('OK', 'Not Found', 'Enhance Your Calm'):
                line = 'HTTP/1.1 {:03d} {}'.format(status, reason).encode()
                if 100 <= status <= 599:
                    self.assertEqual(parse_response_line(line), (status, reason))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_response_line(line)
                    self.assertEqual(str(cm.exception),
                        'bad status: {!r}'.format('{:03d}'.format(status).encode())
                    )

        # Test fast-path when reason is 'OK':
        for status in range(200, 600):
            line = 'HTTP/1.1 {} OK'.format(status).encode()
            tup = parse_response_line(line)
            self.assertEqual(tup, (status, 'OK'))
            self.assertIs(parse_response_line(line)[1], tup[1])

        # Permutations:
        good = b'HTTP/1.1 200 OK'
        self.assertEqual(parse_response_line(good), (200, 'OK'))
        for i in range(len(good)):
            bad = bytearray(good)
            del bad[i]
            with self.assertRaises(ValueError):
                parse_response_line(bytes(bad))
            for j in range(32):
                bad = bytearray(good)
                bad[i] = j
                with self.assertRaises(ValueError):
                    parse_response_line(bytes(bad))

    def test_parse_request_line(self):
        parse_request_line = self.getattr('parse_request_line')
        self.assertEqual(parse_request_line(b'GET / HTTP/1.1'),
            ('GET', '/', [], [], None)
        )


class TestFunctions_C(TestFunctions_Py):
    backend = _base

    def test_parse_header_name(self):
        super().test_parse_header_name()

        # Compare C to Python implementations with the same random values:
        functions = (_base.parse_header_name, _basepy.parse_header_name)
        for i in range(1000):
            bad = os.urandom(32)
            for func in functions:
                exc = 'bad bytes in header name: {!r}'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception), exc, func.__module__)
            bad2 = bad + b'R'
            for func in functions:
                exc = 'header name too long: {!r}...'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad2)
                self.assertEqual(str(cm.exception), exc, func.__module__)
        for i in range(5000):
            good = bytes(random.sample(_basepy.NAME, 32))
            for func in functions:
                ret = func(good)
                self.assertIsInstance(ret, str)
                self.assertEqual(ret, good.decode().lower())


class BodyBackendTestCase(BackendTestCase):
    @property
    def BODY_READY(self):
        return self.getattr('BODY_READY')

    @property
    def BODY_STARTED(self):
        return self.getattr('BODY_STARTED')

    @property
    def BODY_CONSUMED(self):
        return self.getattr('BODY_CONSUMED')

    @property
    def BODY_ERROR(self):
        return self.getattr('BODY_ERROR')

    @property
    def IO_SIZE(self):
        return self.getattr('IO_SIZE')

    @property
    def MAX_IO_SIZE(self):
        return self.getattr('MAX_IO_SIZE')

    @property
    def SocketWrapper(self):
        return self.getattr('SocketWrapper')

    def iter_rfiles(self, data):
        yield io.BytesIO(data)
        yield self.SocketWrapper(MockSocket(data, None))
        yield self.SocketWrapper(MockSocket(data, 1))
        yield self.SocketWrapper(MockSocket(data, 2))

    def check_readonly_attrs(self, body, *members):
        """
        Check body instance attributes that should be read-only.
        """
        assert len(members) >= 2
        if self.backend is _basepy:
            setmsg = "can't set attribute"
            delmsg = "can't delete attribute"
        else:
            setmsg = 'readonly attribute'
            delmsg = 'readonly attribute'
        for name in members:
            value = getattr(body, name)
            with self.assertRaises(AttributeError) as cm:
                setattr(body, name, value)
            self.assertEqual(str(cm.exception), setmsg)
            with self.assertRaises(AttributeError) as cm:
                delattr(body, name)
            self.assertEqual(str(cm.exception), delmsg)


class TestBody_Py(BodyBackendTestCase):
    @property
    def Body(self):
        return self.getattr('Body')

    def test_init(self):
        Body = self.Body
        # Bad content_length value:
        max_uint64 = 2**64 - 1
        max_length = 9999999999999999

        for rfile in self.iter_rfiles(os.urandom(16)):
            self.assertEqual(sys.getrefcount(rfile), 2)
            # Bad content_length type:
            with self.assertRaises(TypeError) as cm:
                Body(rfile, 17.0)
            self.assertEqual(str(cm.exception),
                base._TYPE_ERROR.format('content_length', int, float, 17.0)
            )
            self.assertEqual(sys.getrefcount(rfile), 2)
            with self.assertRaises(TypeError) as cm:
                Body(rfile, '17')
            self.assertEqual(str(cm.exception),
                base._TYPE_ERROR.format('content_length', int, str, '17')
            )
            self.assertEqual(sys.getrefcount(rfile), 2)

        for rfile in self.iter_rfiles(os.urandom(16)):
            for bad in (-max_uint64, -max_length, -17, -1, max_length + 1, max_uint64 + 1):
                with self.assertRaises(ValueError) as cm:
                    Body(rfile, bad)
                self.assertEqual(str(cm.exception),
                    'need 0 <= content_length <= 9999999999999999; got {!r}'.format(bad)
                )

        for rfile in self.iter_rfiles(os.urandom(16)):
            name = ('reader' if type(rfile) is self.SocketWrapper else 'rfile')
            # All good:
            for good in (0, 1, 17, 34969, max_length):
                body = Body(rfile, good)
                self.assertEqual(body.state, self.BODY_READY)
                self.assertIs(body.rfile, rfile)
                self.assertEqual(body.content_length, good)
                self.assertEqual(repr(body),
                    'Body(<{}>, {!r})'.format(name, good)
                )
            self.check_readonly_attrs(body,
                'rfile', 'content_length', 'state', 'chunked'
            )
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

    def test_read(self):
        Body = self.Body
        data = os.urandom(1776)
        rfile = io.BytesIO(data)
        body = Body(rfile, len(data))

        # Bad size type:
        with self.assertRaises(TypeError) as cm:
            body.read(18.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, float, 18.0)
        )
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        with self.assertRaises(TypeError) as cm:
            body.read('18')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, str, '18')
        )
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)

        # size < 0 or size > MAX_IO_SIZE
        toobig = self.MAX_IO_SIZE + 1
        for bad in (-18, -1, toobig):
            body = Body(rfile, 1776)
            with self.assertRaises(ValueError) as cm:
                body.read(bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= {}; got {}'.format(self.MAX_IO_SIZE, bad)
            )
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(rfile.tell(), 0)
            self.assertEqual(body.content_length, 1776)

            body = Body(rfile, toobig)
            with self.assertRaises(ValueError) as cm:
                body.read(bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= {}; got {}'.format(self.MAX_IO_SIZE, bad)
            )
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(rfile.tell(), 0)
            self.assertEqual(body.content_length, toobig)

        # Test when read size > MAX_IO_SIZE:
        rfile = io.BytesIO()
        body = Body(rfile, toobig)
        self.assertEqual(body.content_length, toobig)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'would exceed max read size: 16777217 > 16777216'
        )
        body = Body(rfile, toobig)
        self.assertEqual(body.content_length, toobig)
        with self.assertRaises(ValueError) as cm:
            body.read(None)
        self.assertEqual(str(cm.exception),
            'would exceed max read size: 16777217 > 16777216'
        )

        # Now read it all at once:
        rfile = io.BytesIO(data)
        body = Body(rfile, len(data))
        self.assertEqual(body.read(), data)
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # Read it again, this time in parts:
        rfile = io.BytesIO(data)
        body = Body(rfile, 1776)
        self.assertEqual(body.read(17), data[0:17])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(18), data[17:35])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 35)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(1741), data[35:])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(1776), b'')
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)

        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # ValueError (underflow) when trying to read all:
        rfile = io.BytesIO(data)
        body = Body(rfile, 1800)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'expected to read 1800 bytes, but received 1776'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # Again, but with SocketWrapper:
        sock = MockSocket(data)
        rfile = self.SocketWrapper(sock)
        body = Body(rfile, 1800)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'expected to read 1800 bytes, but received 1776'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, True)

        # ValueError (underflow) error when read in parts:
        data = os.urandom(35)
        rfile = io.BytesIO(data)
        body = Body(rfile, 37)
        self.assertEqual(body.read(18), data[:18])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(body.content_length, 37)
        with self.assertRaises(ValueError) as cm:
            body.read(19)
        self.assertEqual(str(cm.exception),
            'expected to read 19 bytes, but received 17'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # Again, but with SocketWrapper:
        data = os.urandom(35)
        sock = MockSocket(data)
        rfile = self.SocketWrapper(sock)
        body = Body(rfile, 37)
        self.assertEqual(body.read(18), data[:18])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(body.content_length, 37)
        with self.assertRaises(ValueError) as cm:
            body.read(19)
        self.assertEqual(str(cm.exception),
            'expected to read 19 bytes, but received 17'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, True)

        # Test with empty body:
        rfile = io.BytesIO(os.urandom(21))
        body = Body(rfile, 0)
        self.assertEqual(body.read(17), b'')
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 0)
        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # Test with random chunks:
        for i in range(25):
            chunks = random_chunks()
            assert chunks[-1] == b''
            data = b''.join(chunks)
            trailer = os.urandom(17)
            rfile = io.BytesIO(data + trailer)
            body = Body(rfile, len(data))
            for chunk in chunks:
                self.assertEqual(body.read(len(chunk)), chunk)
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), len(data))
            self.assertEqual(body.content_length, len(data))
            with self.assertRaises(ValueError) as cm:
                body.read(17)
            self.assertEqual(str(cm.exception),
                'Body.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(rfile.read(), trailer)

    def test_iter(self):
        Body = self.Body
        data = os.urandom(1776)

        # content_length=0
        rfile = io.BytesIO(data)
        body = Body(rfile, 0)
        self.assertEqual(list(body), [])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(rfile.read(), data)

        # content_length=69
        rfile = io.BytesIO(data)
        body = Body(rfile, 69)
        self.assertEqual(list(body), [data[:69]])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 69)
        self.assertEqual(rfile.read(), data[69:])

        # content_length=1776
        rfile = io.BytesIO(data)
        body = Body(rfile, 1776)
        self.assertEqual(list(body), [data])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(rfile.read(), b'')

        # content_length=1777
        rfile = io.BytesIO(data)
        body = Body(rfile, 1777)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'expected to read 1777 bytes, but received 1776'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # Make sure data is read in IO_SIZE chunks:
        data1 = os.urandom(self.IO_SIZE)
        data2 = os.urandom(self.IO_SIZE)
        length = self.IO_SIZE * 2
        rfile = io.BytesIO(data1 + data2)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with smaller final chunk:
        length = self.IO_SIZE * 2 + len(data)
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with length 1 byte less than available:
        length = self.IO_SIZE * 2 + len(data) - 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data[:-1]])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), data[-1:])

        # Again, with length 1 byte *more* than available:
        length = self.IO_SIZE * 2 + len(data) + 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'expected to read 1777 bytes, but received 1776'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

    def test_write_to(self):
        Body = self.Body
        data1 = os.urandom(17)
        data2 = os.urandom(19)
        rfile = io.BytesIO(data1 + data2)
        wfile = io.BytesIO()
        body = Body(rfile, 17)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.write_to(wfile), 17)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(wfile.tell(), 17)
        self.assertEqual(rfile.read(), data2)
        self.assertEqual(wfile.getvalue(), data1)

class TestBody_C(TestBody_Py):
    backend = _base


class TestChunkedBody_Py(BodyBackendTestCase):
    @property
    def ChunkedBody(self):
        return self.getattr('ChunkedBody')

    def check_common(self, body, rfile):
        name = ('reader' if type(rfile) is self.SocketWrapper else 'rfile')
        self.assertEqual(repr(body), 'ChunkedBody(<{}>)'.format(name))
        self.check_readonly_attrs(body, 'rfile', 'state', 'chunked')
        self.assertIs(body.rfile, rfile)
        self.assertIs(body.chunked, True)
        self.assertEqual(body.state, self.BODY_READY)

    def test_init(self):
        # Test with backend.SocketWrapper:
        sock = MockSocket()
        rfile = self.SocketWrapper(sock)
        self.assertEqual(sys.getrefcount(rfile), 2)
        body = self.ChunkedBody(rfile)
        self.check_common(body, rfile)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Test with arbitrary file-like object:
        rfile = io.BytesIO()
        self.assertEqual(sys.getrefcount(rfile), 2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.check_common(body, rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.SocketWrapper, rfile.readline missing:
        class MissingReadline:
            def readinto(self, dst):
                assert False
        rfile = MissingReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingReadline' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.SocketWrapper, rfile.readline() not callable:
        class BadReadline:
            readline = 'hello'
            def readinto(self, dst):
                assert False
        rfile = BadReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.SocketWrapper, rfile.readline missing:
        class MissingRead:
            def readline(self, size):
                assert False
        rfile = MissingRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingRead' object has no attribute 'readinto'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.SocketWrapper, rfile.readinto() not callable:
        class BadRead:
            readinto = 'hello'
            def readline(self, size):
                assert False
        rfile = BadRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readinto() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

    def test_repr(self):
        data = b'c\r\nhello, world\r\n0;k=v\r\n\r\n'
        for rfile in self.iter_rfiles(data):
            name = ('reader' if type(rfile) is self.SocketWrapper else 'rfile')
            self.assertEqual(sys.getrefcount(rfile), 2)
            body = self.ChunkedBody(rfile)
            self.assertEqual(repr(body), 'ChunkedBody(<{}>)'.format(name))
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

    def test_readchunk(self):
        write_chunk = self.getattr('write_chunk')
    
        rfile = io.BytesIO(b'0\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (None, b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'0;key=value\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (('key', 'value'), b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c\r\nhello, world\r\n0;k=v\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (None, b'hello, world'))
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(body.readchunk(), (('k', 'v'), b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c;key=value\r\nhello, world\r\n0\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (('key', 'value'), b'hello, world'))
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(body.readchunk(), (None, b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        good1 = b'c;k=v\r\n'
        good2 = b'hello, world\r\n'

        class MockFile:
            def __init__(self, ret1, ret2, size=None):
                self.__ret1 = ret1
                self.__ret2 = list(ret2)
                self.__size = size
            
            def readline(self, size):
                assert type(size) is int and size == 4096
                return self.__ret1

            def readinto(self, buf):
                assert type(buf) is memoryview and len(buf) > 0
                if self.__size is not None:
                    return self.__size
                if len(self.__ret2) == 0:
                    return 0
                buf[0] = self.__ret2.pop(0)
                return 1

        # readline() dosen't return bytes:
        rfile = MockFile(bytearray(good1), good2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(TypeError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'need a {!r}; readline() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() returns to many bytes
        bad1 = os.urandom(4097)
        rfile = MockFile(bad1, good2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'readline() returned too many bytes: 4097 > 4096'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() returns bytes, but it doesn't contain a b'\r\n':
        for bad1 in (b'', b'\n', b'\rc\n', b'c\rhello, world', b'c\nhello, world'):
            rfile = MockFile(bad1, good2)
            body = self.ChunkedBody(rfile)
            self.assertEqual(sys.getrefcount(rfile), 5)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad1)
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(rfile), 5)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        # readinto() dosen't return bytes:
        rfile = MockFile(good1, good2, size=14.0)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(TypeError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('received', int, float, 14.0)
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # read() doesn't return the correct amount of data:
        for bad2 in (b'', b'\r\n', b'hello world\r\n'):
            rfile = MockFile(good1, bad2)
            body = self.ChunkedBody(rfile)
            self.assertEqual(sys.getrefcount(rfile), 5)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'expected to read 14 bytes, but received {}'.format(len(bad2))
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(rfile), 5)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        # data isn't correctly terminated:
        bad2 = (b'\r\n' * 6) + b'Az'
        assert len(bad2) == 14
        rfile = MockFile(good1, bad2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception), "bad chunk data termination: b'Az'")
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Now test internal Socket fast-path:
        for bad in (b'', b'\rc\n', b'c\rhello, world', b'c\nhello, world'):
            sock = MockSocket(bad, None)
            rfile = self.SocketWrapper(sock)
            body = self.ChunkedBody(rfile)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad)
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertIs(rfile.closed, True)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)
            self.assertIs(rfile.closed, True)

        sock = MockSocket(b'c\r\nhello, worl\r\n', None)
        rfile = self.SocketWrapper(sock)
        body = self.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'expected to read 1 bytes, but received 0'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertIs(rfile.closed, True)

        for i in range(1, 5):
            chunks = random_chunks2(i)
            wfile = io.BytesIO()
            for chunk in chunks:
                write_chunk(wfile, chunk)
            data = wfile.getvalue()
            del wfile

            for rfile in self.iter_rfiles(data):
                body = self.ChunkedBody(rfile)
                self.assertEqual(body.state, self.BODY_READY)
                for (j, chunk) in enumerate(chunks):
                    if j == 0:
                        self.assertEqual(body.state, self.BODY_READY)
                    else:
                        self.assertEqual(body.state, self.BODY_STARTED)
                    self.assertEqual(body.readchunk(), chunk)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                with self.assertRaises(ValueError) as cm:
                    body.readchunk()
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(body.state, self.BODY_CONSUMED)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            for rfile in self.iter_rfiles(data):
                body = self.ChunkedBody(rfile)
                body = self.ChunkedBody(rfile)
                result = tuple(body)
                self.assertEqual(len(result), len(chunks))
                self.assertEqual(result, chunks)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                with self.assertRaises(ValueError) as cm:
                    tuple(body)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(body.state, self.BODY_CONSUMED)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

    def test_read(self):
        write_chunk = self.getattr('write_chunk')

        for i in range(1, 10):
            chunks = random_chunks2(i)
            data = b''.join(c[1] for c in chunks)
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks:
                total += write_chunk(wfile, chunk)
            cdata = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(cdata), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile

            rfile = io.BytesIO(cdata)
            body = self.ChunkedBody(rfile)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(body.read(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), total)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

            rfile = io.BytesIO(cdata)
            body = self.ChunkedBody(rfile)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(body.read(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), total)
            with self.assertRaises(ValueError) as cm:
                body.read()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(body.state, self.BODY_CONSUMED)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        chunks = tuple(random_chunk(self.MAX_IO_SIZE // 8) for i in range(8))
        one = random_chunk(1)
        empty = random_chunk(0)

        goodchunks = chunks + (empty,)
        data = b''.join(c[1] for c in goodchunks)
        self.assertEqual(len(data), self.MAX_IO_SIZE)
        wfile = io.BytesIO()
        total = 0
        for good in goodchunks:
            total += write_chunk(wfile, good)
        cdata = wfile.getvalue()
        self.assertEqual(wfile.tell(), total)
        self.assertEqual(len(cdata), total)
        self.assertEqual(sys.getrefcount(wfile), 2)
        del wfile

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.read(), data)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), total)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.read(), data)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        badchunks = (one,) + chunks + (empty,)
        data = b''.join(c[1] for c in badchunks)
        wfile = io.BytesIO()
        total = 0
        for bad in badchunks:
            total += write_chunk(wfile, bad)
        cdata = wfile.getvalue()
        self.assertEqual(wfile.tell(), total)
        self.assertEqual(len(cdata), total)
        self.assertEqual(sys.getrefcount(wfile), 2)
        del wfile

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'chunks exceed MAX_IO_SIZE: {} > {}'.format(
                self.MAX_IO_SIZE + 1, self.MAX_IO_SIZE
            )
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'chunks exceed MAX_IO_SIZE: {} > {}'.format(
                self.MAX_IO_SIZE + 1, self.MAX_IO_SIZE
            )
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

    def get_rfile_plus_body(self, data, mock=False, rcvbuf=None):
        if mock is True:
            sock = MockSocket(data, rcvbuf)
            rfile = sock._rfile
            obj = self.SocketWrapper(sock)
        else:
            rfile = io.BytesIO(data)
            obj = rfile
        return (data, rfile, self.ChunkedBody(obj))

    def iter_bodies(self, data, extra):
        for d in (data, data + extra):
            yield self.get_rfile_plus_body(d)
            yield self.get_rfile_plus_body(d, mock=True)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=1)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=2)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=3)

    def test_write_to(self):
        write_chunk = self.getattr('write_chunk')

        extra = os.urandom(1776)
        for count in range(1, 10):
            chunks = random_chunks2(count)
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks:
                total += write_chunk(wfile, chunk)
            data = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(data), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile

            # Normal use-case:
            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                self.assertEqual(body.state, self.BODY_READY)
                self.assertEqual(body.write_to(wfile), total)
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertGreaterEqual(rfile.tell(), total)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Consume, then try again:
            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                self.assertEqual(body.state, self.BODY_READY)
                self.assertEqual(body.write_to(wfile), total)
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertGreaterEqual(rfile.tell(), total)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Use ChunkedBody.readchunk(), then ChunkedBody.write_to()
            for (d, rfile, body) in self.iter_bodies(data, extra):
                self.assertEqual(body.readchunk(), chunks[0])
                if len(chunks) == 1:
                    self.assertEqual(body.state, self.BODY_CONSUMED)
                else:
                    self.assertEqual(body.state, self.BODY_STARTED)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                if len(chunks) == 1:
                    self.assertEqual(str(cm.exception),
                        'ChunkedBody.state == BODY_CONSUMED, already consumed'
                    )
                    self.assertEqual(body.state, self.BODY_CONSUMED)
                else:
                    self.assertEqual(str(cm.exception),
                        'ChunkedBody.state == BODY_STARTED, cannot start another operation'
                    )
                    self.assertEqual(body.state, self.BODY_STARTED)
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Missing the termintating empty chunk data:
            extra = b'ABCDE' * 4096
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks[:-1]:
                total += write_chunk(wfile, chunk)
            data = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(data), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile            

            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)            
                self.assertEqual(str(cm.exception),
                    '{!r} not found in {!r}...'.format(
                        b'\r\n', d[total:total+32]
                    )
                )
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_ERROR)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_ERROR)
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')

                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

class TestChunkedBody_C(TestChunkedBody_Py):
    backend = _base


def get_source_refcounts(source):
    counts = {'': sys.getrefcount(source)}
    for i in range(len(source)):
        base = str(i)
        counts[base] = sys.getrefcount(source[i])
        # Note, it's problematic to check refcounts on None, in both the 
        # Python and C implementations.
        if source[i][0] is not None:
            counts[base + '.ext'] = sys.getrefcount(source[i][0])
            counts[base + '.ext.key'] = sys.getrefcount(source[i][0][0])
            counts[base + '.ext.val'] = sys.getrefcount(source[i][0][1])
        counts[base + '.data'] = sys.getrefcount(source[i][1])
    return counts


def iter_body_sources():
    for count in range(10):
        yield tuple(random_data() for i in range(count))
        source = [random_data() for i in range(count)]
        source.extend([b'' for i in range(3)])
        random.shuffle(source)
        yield tuple(source)


class TestBodyIter_Py(BodyBackendTestCase):
    @property
    def BodyIter(self):
        return self.getattr('BodyIter')

    def test_init(self):
        source = tuple(random_data() for i in range(5))
        content_length = sum(len(part) for part in source)
        self.assertEqual(sys.getrefcount(source), 2)
        body = self.BodyIter(source, content_length)
        self.assertEqual(sys.getrefcount(source), 3)
        self.assertIs(body.source, source)
        self.assertEqual(body.content_length, content_length)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(repr(body),
            'BodyIter(<source>, {})'.format(content_length)
        )
        self.assertEqual(sys.getrefcount(source), 3)
        del body
        self.assertEqual(sys.getrefcount(source), 2)

    def test_write_to(self):
        class BadFile:
            def __init__(self, sizes):
                assert type(sizes) is list
                self.__sizes = sizes

            def write(self, buf):
                ret = self.__sizes.pop(0)
                if isinstance(ret, Exception):
                    raise ret
                return ret

        body = self.BodyIter(None, 17)
        wfile = io.BytesIO()
        with self.assertRaises(TypeError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), "'NoneType' object is not iterable")
        self.assertEqual(body.state, self.BODY_ERROR)
        wfile = io.BytesIO()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception),
            'BodyIter.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)

        for source in iter_body_sources():
            total = sum(len(part) for part in source)
            data = b''.join(source)

            body = self.BodyIter(source, total)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(source), 2)

            body = self.BodyIter(source, total)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'BodyIter.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(wfile.tell(), 0)
            self.assertEqual(wfile.getvalue(), b'')
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(source), 2)

            sizes = tuple(filter(None, (len(part) for part in source)))
            marker1 = random_id()
            marker2 = random_id()
            exc1 = Exception(marker1)
            exc2 = ValueError(marker2)
            for (i, s) in enumerate(sizes):
                for offset in [1, 2, 3]:
                    bad = list(sizes)
                    bad[i] += offset
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'need 0 <= sent <= {}; got {}'.format(s, s + offset)
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

                for b in (str(s), float(s), None):
                    bad = list(sizes)
                    bad[i] = b
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(TypeError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        TYPE_ERROR.format('sent', int, type(b), b)
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

                for exc in (exc1, exc2):
                    bad = list(sizes)
                    bad[i] = exc
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(type(exc)) as cm:
                        body.write_to(wfile)
                    self.assertIs(cm.exception, exc)
                    self.assertEqual(str(cm.exception), str(exc))
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

            if total != 0:
                wfile = io.BytesIO()
                body = self.BodyIter(source, total - 1)
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'exceeds content_length: {} > {}'.format(total, total - 1)
                )
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

            for n in (1, 2, 3):
                wfile = io.BytesIO()
                body = self.BodyIter(source, total + n)
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'deceeds content_length: {} < {}'.format(total, total + n)
                )
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

            for i in range(len(source)):
                badsource = list(source)
                badsource[i] = None
                wfile = io.BytesIO()
                body = self.BodyIter(badsource, total)
                with self.assertRaises(TypeError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    TYPE_ERROR2.format('BodyIter source item', bytes, type(None))
                )
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

class TestBodyIter_C(TestBodyIter_Py):
    backend = _base



class TestChunkedBodyIter_Py(BackendTestCase):
    @property
    def ChunkedBodyIter(self):
        return self.getattr('ChunkedBodyIter')

    @property
    def ChunkedBody(self):
        return self.getattr('ChunkedBody')

    @property
    def BODY_READY(self):
        return self.getattr('BODY_READY')

    @property
    def BODY_CONSUMED(self):
        return self.getattr('BODY_CONSUMED')

    @property
    def BODY_ERROR(self):
        return self.getattr('BODY_ERROR')

    def test_init(self):
        source = random_chunks2()
        self.assertEqual(sys.getrefcount(source), 2)
        body = self.ChunkedBodyIter(source)
        self.assertEqual(sys.getrefcount(source), 3)
        self.assertIs(body.source, source)
        self.assertEqual(body.state, 0)
        self.assertEqual(repr(body), 'ChunkedBodyIter(<source>)')
        self.assertEqual(sys.getrefcount(source), 3)
        del body
        self.assertEqual(sys.getrefcount(source), 2)

    def test_write_to(self):
        ext = ('k', 'v')
        pairs = (
            (
                (
                    (None, b''),
                ),
                b'0\r\n\r\n',
            ),
            (
                (
                    (ext, b''),
                ),
                b'0;k=v\r\n\r\n',
            ),
            (
                (
                    (ext, b'hello, world'),
                    (None, b''),
                ),
                b'c;k=v\r\nhello, world\r\n0\r\n\r\n',
            ),
            (
                (
                    (None, b'hello, world'),
                    (ext, b''),
                ),
                b'c\r\nhello, world\r\n0;k=v\r\n\r\n',
            ),
        )
        for (source, result) in pairs:
            counts = get_source_refcounts(source)
            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), len(result))
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(wfile.getvalue(), result)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2) 
            self.assertEqual(get_source_refcounts(source), counts)

        for n in range(1, 10):
            source = random_chunks2(n)
            counts = get_source_refcounts(source)

            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            total = body.write_to(wfile)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertIs(type(total), int)
            self.assertGreater(total, 4)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            result = wfile.getvalue()
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            if sys.version_info < (3, 5):
                # FIXME: Why does this fail on Python 3.5?
                self.assertEqual(get_source_refcounts(source), counts)

            rfile = io.BytesIO(result)
            rbody = self.ChunkedBody(rfile)
            self.assertEqual(tuple(rbody), source)
            self.assertEqual(rfile.tell(), total)

            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), result)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(body.state, self.BODY_CONSUMED)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            if sys.version_info < (3, 5):
                # FIXME: Why does this fail on Python 3.5?
                self.assertEqual(get_source_refcounts(source), counts)

            # no chunks, or final chunk is not empty:
            bad = list(source)
            del bad[-1]
            bad = tuple(bad)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'final chunk data was not empty'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertTrue(result.startswith(wfile.getvalue()))
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'final chunk data was not empty'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertTrue(result.startswith(wfile.getvalue()))
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_ERROR, cannot be used'
            )
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            del bad
            if sys.version_info < (3, 5):
                # FIXME: Why does this fail on Python 3.5?
                self.assertEqual(get_source_refcounts(source), counts)

            # additional chunk after an empty chunk:
            bad = list(source)
            bad.append(random_chunk(0))
            random.shuffle(bad)
            bad = tuple(bad)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'additional chunk after empty chunk data'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(wfile), 2)
            self.assertGreater(wfile.tell(), 4)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)

            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'additional chunk after empty chunk data'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_ERROR, cannot be used'
            )
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)

            del bad
            if sys.version_info < (3, 5):
                # FIXME: Why does this fail on Python 3.5?
                self.assertEqual(get_source_refcounts(source), counts)


class TestChunkedBodyIter_C(TestChunkedBodyIter_Py):
    backend = _base


class BadSocket:
    def __init__(self, ret):
        self._ret = ret

    def shutdown(self, how):
        pass

    def recv_into(self, buf):
        if isinstance(self._ret, Exception):
            raise self._ret
        return self._ret


################################################################################
# Socket Wrapper:

class TestSocketWrapper_Py(BackendTestCase):
    @property
    def SocketWrapper(self):
        return self.getattr('SocketWrapper')

    def test_init(self):
        class WithCallables:
            def __init__(self, *names, missing=None, notcallable=None):
                for name in names:
                    if name == missing:
                        continue
                    obj = ('nope' if name == notcallable else self._callable)
                    setattr(self, name, obj)

            def _callable(self):
                pass

        names = ('recv_into', 'send', 'close')
        for n in names:
            sock = WithCallables(*names, missing=n)
            with self.assertRaises(AttributeError) as cm:
                self.SocketWrapper(sock)
            self.assertEqual(str(cm.exception),
                "'WithCallables' object has no attribute {!r}".format(n)
            )
            sock = WithCallables(*names, notcallable=n)
            with self.assertRaises(TypeError) as cm:
                self.SocketWrapper(sock)
            self.assertEqual(str(cm.exception),
                'sock.{}() is not callable'.format(n)
            )

        class MockSocket:  
            def __init__(self):
                self._calls = 0

            def recv_into(self, dst):
                assert False

            def send(self, src):
                assert False

            def close(self):
                self._calls += 1

        sock = MockSocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        wrapper = self.SocketWrapper(sock)
        self.assertIs(wrapper.sock, sock)
        self.assertIs(wrapper.closed, False)
        self.assertEqual(sock._calls, 0)
        self.assertIsNone(wrapper.close())
        self.assertEqual(sock._calls, 1)
        self.assertIs(wrapper.closed, True)
        self.assertEqual(sys.getrefcount(sock), 6)
        self.assertEqual(sock._calls, 1)
        del wrapper
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, 1)

    def new(self, data=b'', rcvbuf=None, sndbuf=None):
        sock = MockSocket(data, rcvbuf, sndbuf)
        wrapper = self.SocketWrapper(sock)
        return (sock, wrapper)

    def test_del(self):
        sock = MockSocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        wrapper = self.SocketWrapper(sock)
        self.assertEqual(sys.getrefcount(sock), 6)
        self.assertEqual(sock._calls, [])
        del wrapper
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])

    def test_read_until(self):
        default = self.BUF_LEN
        end = b'\r\n'

        data = os.urandom(2 * default)
        (sock, wrapper) = self.new(data)

        # len(end) == 0:
        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(4096, b'')
        self.assertEqual(str(cm.exception), 'end cannot be empty')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        # size < 0:
        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(-1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got -1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        # size < 1:
        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(0, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 0'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        # size < len(end):
        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(15, os.urandom(16))
        self.assertEqual(str(cm.exception),
            'need 16 <= size <= {}; got 15'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        # size > default:
        with self.assertRaises(ValueError) as cm:
            wrapper.read_until(default + 1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got {}'.format(default, default + 1)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertIs(wrapper.closed, False)

        # No data:
        (sock, wrapper) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(wrapper.read_until(4096, end), b'')
        self.assertEqual(sock._calls, [('recv_into', default)])

        # Main event:
        part1 = os.urandom(1234)
        part2 = os.urandom(2345)
        end = os.urandom(16)
        data = part1 + end + part2 + end
        size = len(data)

        (sock, wrapper) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(wrapper.read_until(size, end), part1)
        self.assertEqual(sock._calls, [('recv_into', default)])
        self.assertEqual(wrapper.read_until(size, end), part2)
        self.assertEqual(sock._calls, [('recv_into', default)])

        nope = os.urandom(16)
        marker = os.urandom(16)
        suffix = os.urandom(666)
        for i in range(318):
            prefix = os.urandom(i)
            data = prefix + marker
            total_data = data + suffix

            # Found:
            (sock, wrapper) = self.new(total_data, 333)
            self.assertEqual(wrapper.read_until(333, marker), prefix)
            self.assertEqual(sock._calls, [('recv_into', default)])

            # Not found:
            (sock, wrapper) = self.new(total_data, 333)
            with self.assertRaises(ValueError) as cm:
                wrapper.read_until(333, nope)
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(nope, total_data[:32])
            )
            self.assertEqual(sock._calls, [('recv_into', default)])

    def check_read_request(self, rcvbuf):
        # Empty preamble:
        (sock, wrapper) = self.new(b'', rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            wrapper.read_request()
        self.assertEqual(str(cm.exception), 'request preamble is empty')

        # Good preamble termination:
        prefix = b'GET / HTTP/1.1'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        data = prefix + term + suffix
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        request = wrapper.read_request()
        self.assertIsInstance(request, self.getattr('Request'))
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.uri, '/')
        self.assertEqual(request.headers, {})
        self.assertIsNone(request.body)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, [])
        self.assertIsNone(request.query)

        # Bad preamble termination:
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                wrapper.read_request()
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )

        # Request line too short
        for i in range(len(prefix)):
            bad = bytearray(prefix)
            del bad[i]
            bad = bytes(bad)
            data = bad + term + suffix
            (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                wrapper.read_request()
            self.assertEqual(str(cm.exception),
                'request line too short: {!r}'.format(bad)
            )

        # With Range header:
        data = b'GET / HTTP/1.1\r\nRange: bytes=0-0\r\n\r\n'
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        request = wrapper.read_request()
        self.assertIsInstance(request, self.getattr('Request'))
        self.assertEqual(request.method, 'GET')
        self.assertEqual(request.uri, '/')
        self.assertEqual(request.headers, {'range': self.api.Range(0, 1)})
        self.assertIsNone(request.body)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, [])
        self.assertIsNone(request.query)
        _range = request.headers['range']
        self.assertIs(type(_range), self.api.Range)
        self.assertIs(type(_range.start), int)
        self.assertIs(type(_range.stop), int)
        self.assertEqual(_range.start, 0)
        self.assertEqual(_range.stop, 1)
        self.assertEqual(repr(_range), 'Range(0, 1)')
        self.assertEqual(str(_range), 'bytes=0-0')

        # With Body:
        marker = os.urandom(16)
        data = b'PUT /foo HTTP/1.1\r\nContent-Length: 16\r\n\r\n' + marker
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        request = wrapper.read_request()
        self.assertIsInstance(request, self.getattr('Request'))
        self.assertEqual(request.method, 'PUT')
        self.assertEqual(request.uri, '/foo')
        self.assertEqual(request.headers, {'content-length': 16})
        self.assertIsInstance(request.body, self.api.Body)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, ['foo'])
        self.assertIsNone(request.query)
        self.assertEqual(request.body.content_length, 16)
        self.assertEqual(request.body.read(), marker)

        # With ChunkedBody:
        marker = os.urandom(15)
        body = b'f\r\n' + marker + b'\r\n0\r\n\r\n'
        data = b'PUT /foo HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n' + body
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        request = wrapper.read_request()
        self.assertIsInstance(request, self.getattr('Request'))
        self.assertEqual(request.method, 'PUT')
        self.assertEqual(request.uri, '/foo')
        self.assertEqual(request.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(request.body, self.api.ChunkedBody)
        self.assertEqual(request.mount, [])
        self.assertEqual(request.path, ['foo'])
        self.assertIsNone(request.query)
        self.assertEqual(list(request.body), [(None, marker), (None, b'')])

    def test_read_request(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_request(rcvbuf)

    def check_read_response(self, rcvbuf):
        ResponseType = self.getattr('ResponseType')

        # Bad method:
        for method in BAD_METHODS:
            (sock, wrapper) = self.new()
            with self.assertRaises(ValueError) as cm:
                wrapper.read_response(method)
            self.assertEqual(str(cm.exception),
                'bad method: {!r}'.format(method)
            )

        # Test when exact b'\r\n\r\n' preamble termination is missing:
        data = b'HTTP/1.1 200 OK\n\r\nhello, world'
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        with self.assertRaises(ValueError) as cm:
            wrapper.read_response('GET')
        self.assertEqual(str(cm.exception),
            '{!r} not found in {!r}...'.format(b'\r\n\r\n', data)
        )
        if rcvbuf is None:
            self.assertEqual(sock._calls_recv_into, 2)
        else:
            self.assertEqual(sock._calls_recv_into, len(data) // rcvbuf + 1)

        prefix = b'HTTP/1.1 200 OK'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                wrapper.read_response('GET')
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )

        (sock, wrapper) = self.new(rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            wrapper.read_response('GET')
        self.assertEqual(str(cm.exception), 'response preamble is empty')
        if rcvbuf is None:
            self.assertEqual(sock._calls_recv_into, 1)
        else:
            self.assertEqual(sock._calls_recv_into, 1)

        data = b'HTTP/1.1 200 OK\r\n\r\nHello naughty nurse!'
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        response = wrapper.read_response('GET')
        self.assertIsInstance(response, ResponseType)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {})
        self.assertIs(response.body, None)
        self.assertEqual(response, (200, 'OK', {}, None))

        good = b'HTTP/1.1 200 OK'
        suffix = b'\r\n\r\nHello naughty nurse!'
        for i in range(len(good)):
            bad = bytearray(good)
            del bad[i]
            bad = bytes(bad)
            data = bad + suffix
            (sock, wraper) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                wraper.read_response('GET')
            self.assertEqual(str(cm.exception),
                'response line too short: {!r}'.format(bad)
            )
        indexes = list(range(9))
        indexes.append(12)
        for i in indexes:
            g = good[i]
            for b in range(256):
                if b == g:
                    continue
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                data = bad + suffix
                (sock, wraper) = self.new(data, rcvbuf=rcvbuf)
                with self.assertRaises(ValueError) as cm:
                    wraper.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad response line: {!r}'.format(bad)
                )

        template = 'HTTP/1.1 {:03d} OK\r\n\r\nHello naughty nurse!'
        for status in range(1000):
            data = template.format(status).encode()
            (sock, wraper) = self.new(data, rcvbuf=rcvbuf)
            if 100 <= status <= 599:
                response = wraper.read_response('GET')
                self.assertIsInstance(response, ResponseType)
                self.assertEqual(response.status, status)
                self.assertEqual(response.reason, 'OK')
                self.assertEqual(response.headers, {})
                self.assertIs(response.body, None)
                self.assertEqual(response, (status, 'OK', {}, None))
            else:
                with self.assertRaises(ValueError) as cm:
                    wraper.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad status: {!r}'.format('{:03d}'.format(status).encode())
                )

        # With Body:
        marker = os.urandom(16)
        data = b'HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n' + marker
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        response = wrapper.read_response('GET')
        self.assertIsInstance(response, ResponseType)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 16})
        self.assertIsInstance(response.body, self.api.Body)
        self.assertEqual(response.body.content_length, 16)
        self.assertEqual(response.body.read(), marker)

        # With ChunkedBody:
        marker = os.urandom(15)
        body = b'f\r\n' + marker + b'\r\n0\r\n\r\n'
        data = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + body
        (sock, wrapper) = self.new(data, rcvbuf=rcvbuf)
        response = wrapper.read_response('GET')
        self.assertIsInstance(response, ResponseType)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'transfer-encoding': 'chunked'})
        self.assertIsInstance(response.body, self.api.ChunkedBody)
        self.assertEqual(list(response.body), [(None, marker), (None, b'')])

    def test_read_response(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_response(rcvbuf)

    def test_write_request(self):
        (sock, wrapper) = self.new()
        for method in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:
                wrapper.write_request(method, '/', {}, None)
            self.assertEqual(str(cm.exception),
                'bad method: {!r}'.format(method)
            )

        # Empty headers, no body:
        (sock, wrapper) = self.new()
        headers = {}
        self.assertEqual(wrapper.write_request('GET', '/', headers, None), 18)
        self.assertEqual(headers, {})
        self.assertEqual(sock._wfile.getvalue(), b'GET / HTTP/1.1\r\n\r\n')

        # One header:
        headers = {'foo': 17}  # Make sure to test with int header value
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, None), 27)
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        headers = {'foo': 17, 'bar': 'baz'}
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, None), 37)
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        (sock, wrapper) = self.new()
        headers = {}
        self.assertEqual(
            wrapper.write_request('GET', '/', headers, b'hello'),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is bytes longer than MAX_IO_SIZE:
        MAX_IO_SIZE = self.MAX_IO_SIZE
        (sock, wrapper) = self.new()
        headers = {}
        body = os.urandom(MAX_IO_SIZE + 1)
        with self.assertRaises(ValueError) as cm:
            wrapper.write_request('GET', '/', headers, body)
        self.assertEqual(str(cm.exception),
            'need len(body) <= {}; got {}'.format(MAX_IO_SIZE, len(body))
        )

        # body is base.Body:
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = self.api.Body(rfile, 5)
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, body), 42)
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.BodyIter:
        headers = {}
        body = self.api.BodyIter((b'hell', b'o'), 5)
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, body), 42)
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = self.api.ChunkedBody(rfile)
        headers = {}
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, body), 61)
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.ChunkedBodyIter:
        headers = {}
        body = self.api.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        (sock, wrapper) = self.new()
        self.assertEqual(wrapper.write_request('GET', '/', headers, body), 61)
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

    def test_write_response(self):
        # Empty headers, no body:
        (sock, wrapper) = self.new()
        headers = {}
        self.assertEqual(wrapper.write_response(200, 'OK', headers, None), 19)
        self.assertEqual(headers, {})
        self.assertEqual(sock._wfile.tell(), 19)
        self.assertEqual(sock._wfile.getvalue(), b'HTTP/1.1 200 OK\r\n\r\n')

        # One header:
        (sock, wrapper) = self.new()
        headers = {'foo': 17}  # Make sure to test with int header value
        self.assertEqual(wrapper.write_response(200, 'OK', headers, None), 28)
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(sock._wfile.tell(), 28)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        (sock, wrapper) = self.new()
        headers = {'foo': 17, 'bar': 'baz'}
        self.assertEqual(wrapper.write_response(200, 'OK', headers, None), 38)
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(sock._wfile.tell(), 38)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        (sock, wrapper) = self.new()
        headers = {}
        self.assertEqual(
            wrapper.write_response(200, 'OK', headers, b'hello'),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(sock._wfile.tell(), 43)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is bytes longer than MAX_IO_SIZE:
        MAX_IO_SIZE = self.MAX_IO_SIZE
        (sock, wrapper) = self.new()
        headers = {}
        body = os.urandom(MAX_IO_SIZE + 1)
        with self.assertRaises(ValueError) as cm:
            wrapper.write_response(200, 'OK', headers, body)
        self.assertEqual(str(cm.exception),
            'need len(body) <= {}; got {}'.format(MAX_IO_SIZE, len(body))
        )

        # body is base.BodyIter:
        (sock, wrapper) = self.new()
        headers = {}
        body = self.api.BodyIter((b'hell', b'o'), 5)
        self.assertEqual(wrapper.write_response(200, 'OK', headers, body), 43)
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(sock._wfile.tell(), 43)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBodyIter:
        (sock, wrapper) = self.new()
        headers = {}
        body = self.api.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        self.assertEqual(wrapper.write_response(200, 'OK', headers, body), 62)
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(sock._wfile.tell(), 62)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.Body:
        (sock, wrapper) = self.new()
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = self.api.Body(rfile, 5)
        self.assertEqual(wrapper.write_response(200, 'OK', headers, body), 43)
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(sock._wfile.tell(), 43)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        (sock, wrapper) = self.new()
        headers = {}
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = self.api.ChunkedBody(rfile)
        self.assertEqual(wrapper.write_response(200, 'OK', headers, body), 62)
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(sock._wfile.tell(), 62)
        self.assertEqual(sock._wfile.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )


class TestSocketWrapper_C(TestSocketWrapper_Py):
    backend = _base



class TestSession_Py(BackendTestCase):
    @property
    def Session(self):
        return self.getattr('Session')

    def test_init(self):
        address = random_id()
        ncount = sys.getrefcount(None)
        sess = self.Session(address)
        self.assertIs(sess.address, address)
        self.assertIsNone(sess.credentials)
        self.assertIs(type(sess.max_requests), int)
        self.assertEqual(sess.max_requests, 500)
        self.assertIs(type(sess.requests), int)
        self.assertEqual(sess.requests, 0)
        store = sess.store
        self.assertIs(type(store), dict)
        self.assertEqual(sess.store, {})
        self.assertIs(sess.store, store)
        self.assertIs(sess.closed, False)
        self.assertIsNone(sess.message)
        self.assertEqual(repr(sess),
            'Session({!r})'.format(address)
        )
        self.assertEqual(str(sess), repr(address))
        del sess
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(None), ncount)
        self.assertEqual(sys.getrefcount(store), 2)
    
        address = random_id()
        credentials = None
        ccount = sys.getrefcount(credentials)
        max_requests = 75000
        mrcount = sys.getrefcount(max_requests)
        sess = self.Session(address, credentials, max_requests)
        self.assertIs(sess.address, address)
        self.assertIs(sess.credentials, credentials)
        self.assertIs(type(sess.max_requests), int)
        self.assertEqual(sess.max_requests, 75000)
        self.assertIs(type(sess.requests), int)
        self.assertEqual(sess.requests, 0)
        store = sess.store
        self.assertIs(type(store), dict)
        self.assertEqual(sess.store, {})
        self.assertIs(sess.store, store)
        self.assertIs(sess.closed, False)
        self.assertIsNone(sess.message)
        self.assertEqual(repr(sess),
            'Session({!r})'.format(address)
        )
        self.assertEqual(str(sess), repr(address))
        del sess
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)
        self.assertEqual(sys.getrefcount(store), 2)

        credentials = (32181, 1000, 1000)
        ccount = sys.getrefcount(credentials)
        max_requests = 75000
        mrcount = sys.getrefcount(max_requests)
        sess = self.Session(address, credentials, max_requests)
        self.assertIs(sess.address, address)
        self.assertIs(sess.credentials, credentials)
        self.assertIs(type(sess.max_requests), int)
        self.assertEqual(sess.max_requests, 75000)
        self.assertIs(type(sess.requests), int)
        self.assertEqual(sess.requests, 0)
        store = sess.store
        self.assertIs(type(store), dict)
        self.assertEqual(sess.store, {})
        self.assertIs(sess.store, store)
        self.assertIs(sess.closed, False)
        self.assertIsNone(sess.message)
        self.assertEqual(repr(sess),
            'Session({!r}, {!r})'.format(address, credentials)
        )
        self.assertEqual(str(sess), '{!r} {!r}'.format(address, credentials))
        del sess
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)
        self.assertEqual(sys.getrefcount(store), 2)

        # credentials isn't a tuple:
        credentials = [32181, 1000, 1000]
        ccount = sys.getrefcount(credentials)
        with self.assertRaises(TypeError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            "credentials: need a <class 'tuple'>; got a <class 'list'>"
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

        # credentials is a 2-tuple:
        credentials = (32181, 1000)
        ccount = sys.getrefcount(credentials)
        with self.assertRaises(ValueError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            'credentials: need a 3-tuple; got a 2-tuple'
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

        # credentials is a 4-tuple:
        credentials = (32181, 1000, 1000, 1000)
        ccount = sys.getrefcount(credentials)
        with self.assertRaises(ValueError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            'credentials: need a 3-tuple; got a 4-tuple'
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

        credentials = (12345, 23456, 345678)
        ccount = sys.getrefcount(credentials)

        # max_requests isn't an int:
        max_requests = 75000.0
        mrcount = sys.getrefcount(max_requests)
        with self.assertRaises(TypeError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            "max_requests: need a <class 'int'>; got a <class 'float'>: 75000.0"
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

        # max_requests < 0:
        max_requests = -1
        mrcount = sys.getrefcount(max_requests)
        with self.assertRaises(ValueError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            'need 0 <= max_requests <= 75000; got -1'
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

        # max_requests > 75000
        max_requests = 75001
        mrcount = sys.getrefcount(max_requests)
        with self.assertRaises(ValueError) as cm:
            self.Session(address, credentials, max_requests)
        self.assertEqual(str(cm.exception),
            'need 0 <= max_requests <= 75000; got 75001'
        )
        self.assertEqual(sys.getrefcount(address), 2)
        self.assertEqual(sys.getrefcount(credentials), ccount)
        self.assertEqual(sys.getrefcount(max_requests), mrcount)

class TestSession_C(TestSession_Py):
    backend = _base


class TestServerFunctions_Py(BackendTestCase):
    def test_handle_requests(self):
        handle_requests = self.getattr('_handle_requests')
        Session = self.getattr('Session')

        # Session isn't a backend.Session instance:
        def app(session, request, bodies):
            assert False

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        ses = {'client': ('127.0.0.1', 12345)}
        with self.assertRaises(TypeError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'session: need a {!r}; got a {!r}'.format(Session, dict)
        )
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, ['close'])

        ses = Session(('127.0.0.1', 12345), None, 25)

        # app() returns neither a tuple nor Response namedtuple:
        rsp = [200, 'OK', {}, b'hello, world']
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(TypeError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'response: need a {!r}; got a {!r}'.format(tuple, list)
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() returns a 3-tuple:
        rsp = (200, 'OK', {})
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'response: need a 4-tuple; got a 3-tuple'
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() returns a 5-tuple:
        rsp = (200, 'OK', {}, b'hello', b'world')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'response: need a 4-tuple; got a 5-tuple'
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() returns status that isn't an int:
        rsp = ('200', 'OK', {}, b'hello, world')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(TypeError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('status', int, str, '200')
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() returns status < 100:
        rsp = (99, 'OK', {}, b'hello, world')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'need 100 <= status <= 599; got 99'
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() returns status > 599:
        rsp = (600, 'OK', {}, b'hello, world')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'GET /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'need 100 <= status <= 599; got 600'
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() doesn't consume request body:
        rsp = (200, 'OK', {}, None)
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'PUT'
            assert request.uri == '/foo'
            assert request.headers == {'content-length': 3}
            assert type(request.body) is bodies.Body
            assert request.body.content_length == 3
            return rsp

        data = b'PUT /foo HTTP/1.1\r\nContent-Length: 3\r\n\r\nbar'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            'request body not consumed: Body(<reader>, 3)'
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() doesn't return response body None for HEAD request:
        rsp = (200, 'OK', {}, b'hello, world')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'HEAD'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        data = b'HEAD /foo HTTP/1.1\r\n\r\n'
        sock = MockSocket(data)
        with self.assertRaises(TypeError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception),
            "request method is HEAD, but response body is not None: <class 'bytes'>" 
        )
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', 32 * 1024), 'close'])
        self.assertEqual(sys.getrefcount(rsp), 2)

        # app() raises an exception:
        marker = random_id()
        exc = ValueError(marker)
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'PUT'
            assert request.uri == '/foo'
            assert request.headers == {'content-length': 3}
            assert type(request.body) is bodies.Body
            assert request.body.content_length == 3
            raise exc

        data = b'PUT /foo HTTP/1.1\r\nContent-Length: 3\r\n\r\nbar'
        sock = MockSocket(data)
        with self.assertRaises(ValueError) as cm:
            handle_requests(app, ses, sock)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)
        self.assertEqual(ses.requests, 0)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', self.BUF_LEN), 'close'])

        # EmptyPreambleError:
        def app(session, request, bodies):
            assert False

        sock = MockSocket(b'')
        with self.assertRaises(self.EmptyPreambleError) as cm:
            handle_requests(app, ses, sock)
        self.assertEqual(str(cm.exception), 'request preamble is empty')
        self.assertEqual(ses.requests, 0)
        self.assertIs(ses.closed, False)
        self.assertIsNone(ses.message)
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [('recv_into', self.BUF_LEN), 'close'])

        # Should close connection after max_requests:
        rsp = (200, 'OK', {}, b'bar')
        def app(session, request, bodies):
            assert session is ses
            assert request.method == 'GET'
            assert request.uri == '/foo'
            assert request.headers == {}
            assert request.body is None
            return rsp

        indata = b'GET /foo HTTP/1.1\r\n\r\n'
        outdata = b'HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nbar'
        sock = MockSocket(indata * 3)
        ses = Session(('127.0.0.1', 12345), None, 2)
        self.assertIsNone(handle_requests(app, ses, sock))
        self.assertEqual(ses.requests, 2)
        self.assertIs(ses.closed, True)
        self.assertEqual(ses.message, 'max_requests')
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [
            ('recv_into', 32 * 1024),
            ('send', len(outdata)),
            ('send', len(outdata)),
            'close',
        ])
        self.assertEqual(sys.getrefcount(rsp), 2)
        self.assertEqual(sock._rfile.read(), b'')
        self.assertEqual(sock._wfile.getvalue(), outdata * 2)

        # Should close connection when status >= 400 and not 404, 409, 412:
        class App:
            def __init__(self):
                self._status_list = [404, 409, 412, 400, 200]

            def __call__(self, session, request, bodies):
                assert session is ses
                assert request.method == 'GET'
                assert request.uri == '/foo'
                assert request.headers == {}
                assert request.body is None
                status = self._status_list.pop(0)
                return (status, 'OK', {}, b'bar')

        app = App()
        indata = b'GET /foo HTTP/1.1\r\n\r\n'
        out = 'HTTP/1.1 {} OK\r\ncontent-length: 3\r\n\r\nbar'
        out1 = out.format(404).encode()
        out2 = out.format(409).encode()
        out3 = out.format(412).encode()
        out4 = out.format(400).encode()
        sock = MockSocket(indata * 10)
        ses = Session(('127.0.0.1', 12345), None, 10)
        self.assertIsNone(handle_requests(app, ses, sock))
        self.assertEqual(ses.requests, 4)
        self.assertIs(ses.closed, True)
        self.assertEqual(ses.message, '400 OK')
        self.assertEqual(sys.getrefcount(app), 2)
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(ses), 2)
        self.assertEqual(sock._calls, [
            ('recv_into', 32 * 1024),
            ('send', len(out1)),
            ('send', len(out2)),
            ('send', len(out3)),
            ('send', len(out4)),
            'close',
        ])
        self.assertEqual(sock._rfile.read(), b'')
        self.assertEqual(sock._wfile.getvalue(), out1 + out2 + out3 + out4)
        self.assertEqual(app._status_list, [200])


class TestServerFunctions_C(TestServerFunctions_Py):
    backend = _base


class TestConnection_Py(BackendTestCase):
    @property
    def Connection(self):
        return getattr(self.backend, 'Connection')

    @property
    def ResponseType(self):
        return getattr(self.backend, 'ResponseType')

    @property
    def Body(self):
        return getattr(self.backend, 'Body')

    @property
    def Range(self):
        return getattr(self.backend, 'Range')

    @property
    def ContentRange(self):
        return getattr(self.backend, 'ContentRange')

    def iter_bodies(self):
        data = b'hello, world'
        yield data
        yield self.api.Body(io.BytesIO(data), len(data))
        yield self.api.BodyIter([data], len(data))
        yield self.api.ChunkedBody(io.BytesIO(b'0\r\n\r\n'))
        yield self.api.ChunkedBodyIter([(None, b'')])

    def iter_all_bodies(self):
        yield None
        yield from self.iter_bodies()

    def test_init(self):
        class BaseMockSocket:
            __slots__ = ('_calls',)

            def __init__(self):
                self._calls = []

            def shutdown(self, how):
                self._calls.append(('shutdown', how))

            def close(self):
                self._calls.append('close')
    
        # no sock.recv_into() attribute:
        class BadSocket1(BaseMockSocket):
            __slots__ = tuple()
            def send(self, src):
                assert False
        sock = BadSocket1()
        with self.assertRaises(AttributeError) as cm:
            self.Connection(sock, None)
        self.assertEqual(str(cm.exception),
            "'BadSocket1' object has no attribute 'recv_into'"
        )
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])

        # no sock.send() attribute:
        class BadSocket2(BaseMockSocket):
            __slots__ = tuple()
            def recv_into(self, src):
                assert False
        sock = BadSocket2()
        with self.assertRaises(AttributeError) as cm:
            self.Connection(sock, None)
        self.assertEqual(str(cm.exception),
            "'BadSocket2' object has no attribute 'send'"
        )
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])

        # sock.recv_into() isn't callable:
        class BadSocket3(BaseMockSocket):
            __slots__ = tuple()
            recv_into = 'hello, world'
            def send(self, src):
                assert False
        sock = BadSocket3()
        with self.assertRaises(TypeError) as cm:
            self.Connection(sock, None)
        self.assertEqual(str(cm.exception),
            'sock.recv_into() is not callable'
        )
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])

        # sock.send() isn't callable:
        class BadSocket4(BaseMockSocket):
            __slots__ = tuple()
            send = 'hello, world'
            def recv_into(self, src):
                assert False
        sock = BadSocket4()
        with self.assertRaises(TypeError) as cm:
            self.Connection(sock, None)
        self.assertEqual(str(cm.exception),
            'sock.send() is not callable'
        )
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])

        # base_headers is neither None nor a dict:
        sock = MockSocket()
        base_headers = [('foo', 'bar')]
        with self.assertRaises(TypeError) as cm:
            self.Connection(sock, base_headers)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR2.format('base_headers', tuple, list)
        )
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(base_headers), 2)
        self.assertEqual(sock._calls, ['close'])
        self.assertEqual(base_headers, [('foo', 'bar')])

        # Good sock, base_headers is None:
        api = self.api
        count = sys.getrefcount(api)
        sock = MockSocket()
        conn = self.Connection(sock, None)
        self.assertEqual(sys.getrefcount(sock), 7)
        self.assertIs(conn.sock, sock)
        self.assertIsNone(conn.base_headers)
        self.assertIs(conn.api, api)
        self.assertIs(conn.bodies, api)  # Deprecated alias for `Connection.api`
        self.assertIs(conn.closed, False)
        self.assertEqual(sock._calls, [])
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, ['close'])
        self.assertEqual(sys.getrefcount(api), count)

        # Good sock, base_headers is a tuple:
        sock = MockSocket()
        k = random_id().lower()
        v = random_id()
        base_headers = ((k, v),)
        conn = self.Connection(sock, base_headers)
        self.assertEqual(sys.getrefcount(sock), 7)
        self.assertIs(conn.sock, sock)
        self.assertIs(conn.base_headers, base_headers)
        self.assertIs(conn.api, api)
        self.assertIs(conn.bodies, api)  # Deprecated alias for `Connection.api`
        self.assertIs(conn.closed, False)
        self.assertEqual(sock._calls, [])
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(base_headers), 2)
        self.assertEqual(sock._calls, ['close'])
        self.assertEqual(sys.getrefcount(api), count)

    def test_close(self):
        sock = MockSocket()
        conn = self.Connection(sock, None)
        self.assertIs(conn.closed, False)
        self.assertIsNone(conn.close())
        self.assertIs(conn.closed, True)
        self.assertEqual(sock._calls, ['close'])

        # Calling Connection.close() again shouldn't call sock.close(),
        # sock.close():
        self.assertIsNone(conn.close())
        self.assertIs(conn.closed, True)
        self.assertEqual(sock._calls, ['close'])

        class SpecialMockSocket(MockSocket):
            def __init__(self, ret, data=b'', rcvbuf=None, sndbuf=None):
                super().__init__(data, rcvbuf, sndbuf)
                self.ret = ret

            def close(self):
                super().close()
                if isinstance(self.ret, Exception):
                    raise self.ret
                return self.ret

        # Sould return value returned by sock.close():
        marker = random_id()
        sock = SpecialMockSocket(marker)
        conn = self.Connection(sock, None)
        self.assertIs(conn.close(), marker)
        self.assertEqual(sock._calls, ['close'])
        self.assertIs(conn.closed, True)
        self.assertIsNone(conn.close())
        self.assertEqual(sock._calls, ['close'])
        self.assertIs(conn.closed, True)

        # Sould raise exception raised by sock.close():
        exc = ValueError(marker)
        sock = SpecialMockSocket(exc)
        conn = self.Connection(sock, None)
        with self.assertRaises(ValueError) as cm:
            conn.close()
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)
        self.assertEqual(sock._calls, ['close'])
        self.assertIs(conn.closed, True)
        self.assertIsNone(conn.close())
        self.assertEqual(sock._calls, ['close'])
        self.assertIs(conn.closed, True)

    def test_request(self):
        # Make sure method is validated:
        for method in GOOD_METHODS:
            for bad in (method.encode(), str_subclass(method)):
                sock = MockSocket()
                conn = self.Connection(sock, None)
                with self.assertRaises(TypeError) as cm:
                    conn.request(bad, '/foo', {}, None)
                self.assertEqual(str(cm.exception),
                    TYPE_ERROR.format('method', str, type(bad), bad)
                )
        for bad in BAD_METHODS:
            sock = MockSocket()
            conn = self.Connection(sock, None)
            with self.assertRaises(ValueError) as cm:
                conn.request(bad, '/foo', {}, None)
            self.assertEqual(str(cm.exception),
                'bad method: {!r}'.format(bad)
            )

        # Test when connection is closed:
        sock = MockSocket()
        conn = self.Connection(sock, None)
        self.assertIsNone(conn.close())
        self.assertEqual(sock._calls, ['close'])
        sock._calls.clear()
        with self.assertRaises(ValueError) as cm:
            conn.request('GET', '/', {}, None)
        self.assertEqual(str(cm.exception),
            'Connection is closed'
        )
        del conn
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 2)

        send = b'GET / HTTP/1.1\r\n\r\n'
        recv = b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello, world'

        # Previous response body not consumed:
        sock = MockSocket(recv * 2)
        conn = self.Connection(sock, None)
        response = conn.request('GET', '/', {}, None)
        self.assertIs(conn.closed, False)
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {'content-length': 12})
        self.assertIs(type(response.body), self.Body)
        self.assertEqual(sock._calls, [
            ('send', 18),
            ('recv_into', 32768),
        ])
        self.assertEqual(sock._wfile.getvalue(), send)
        self.assertEqual(sock._rfile.tell(), len(recv) * 2)
        sock._calls.clear()
        with self.assertRaises(ValueError) as cm:
            conn.request('GET', '/', {}, None)
        self.assertEqual(str(cm.exception),
            'response body not consumed: {!r}'.format(response.body)
        )
        self.assertIs(conn.closed, True)
        self.assertEqual(sock._calls, ['close'])
        self.assertEqual(sock._wfile.getvalue(), send)
        self.assertEqual(sock._rfile.tell(), len(recv) * 2)
        sock._calls.clear()
        del conn
        self.assertEqual(sys.getrefcount(sock), 6)
        del response
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sock._calls, [])

        v = (None, 1, 2, 3)
        comb = tuple((s, r) for s in v for r in v)
        for (r, s) in comb:
            sock = MockSocket(recv, rcvbuf=r, sndbuf=s)
            conn = self.Connection(sock, None)
            h = {}
            response = conn.request('GET', '/', h, None)
            self.assertEqual(h, {})
            self.assertIs(type(response), self.ResponseType)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.reason, 'OK')
            self.assertEqual(response.headers, {'content-length': 12})
            self.assertIs(type(response.body), self.Body)
            self.assertEqual(response.body.read(), b'hello, world')
            self.assertEqual(sys.getrefcount(sock), 7)
            del response
            del conn
            self.assertEqual(sys.getrefcount(sock), 2)

            sock = MockSocket(recv, rcvbuf=r, sndbuf=s)
            k = random_id().lower()
            v = random_id()
            bh = ((k, v),)
            conn = self.Connection(sock, bh)
            h = {}
            response = conn.request('GET', '/', h, None)
            self.assertEqual(h, {k: v})
            self.assertEqual(sys.getrefcount(h), 2)
            self.assertIs(type(response), self.ResponseType)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.reason, 'OK')
            self.assertEqual(response.headers, {'content-length': 12})
            self.assertIs(type(response.body), self.Body)
            self.assertEqual(response.body.read(), b'hello, world')
            self.assertEqual(sys.getrefcount(sock), 7)
            del response
            del conn
            self.assertEqual(sys.getrefcount(sock), 2)
            self.assertEqual(sys.getrefcount(bh), 2)

        for method in GOOD_METHODS:
            for body in self.iter_bodies():
                sock = MockSocket(recv)
                conn = self.Connection(sock, None)
                h = {}
                if method in {'PUT', 'POST'}:
                    response = conn.request(method, '/', h, body)
                    self.assertEqual(len(h), 1)
                    self.assertEqual(sys.getrefcount(h), 2)
                    self.assertIs(type(response), self.ResponseType)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.reason, 'OK')
                    self.assertEqual(response.headers, {'content-length': 12})
                    self.assertIs(type(response.body), self.Body)
                    self.assertEqual(response.body.read(), b'hello, world')
                else:
                    with self.assertRaises(ValueError) as cm:
                        conn.request(method, '/foo', h, body)
                    self.assertEqual(str(cm.exception),
                        'when method is {!r}, body must be None; got a {!r}'.format(
                            method, type(body)   
                        )
                    )
                    self.assertEqual(h, {})
                    self.assertIs(conn.closed, True)
                    self.assertEqual(sock._calls, ['close'])

    def test_put(self):
        sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
        conn = self.Connection(sock, None)
        response = conn.put('/', {}, None)
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response, (200, 'OK', {}, None))
        self.assertEqual(sock._wfile.getvalue(), b'PUT / HTTP/1.1\r\n\r\n')
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)
        for body in self.iter_all_bodies():
            sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
            conn = self.Connection(sock, None)
            response = conn.put('/', {}, body)
            self.assertIs(type(response), self.ResponseType)
            self.assertEqual(response, (200, 'OK', {}, None))
            del conn
            self.assertEqual(sys.getrefcount(sock), 2)

    def test_post(self):
        sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
        conn = self.Connection(sock, None)
        response = conn.post('/', {}, None)
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response, (200, 'OK', {}, None))
        self.assertEqual(sock._wfile.getvalue(), b'POST / HTTP/1.1\r\n\r\n')
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)
        for body in self.iter_all_bodies():
            sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
            conn = self.Connection(sock, None)
            response = conn.post('/', {}, body)
            self.assertIs(type(response), self.ResponseType)
            self.assertEqual(response, (200, 'OK', {}, None))
            del conn
            self.assertEqual(sys.getrefcount(sock), 2)

    def test_get(self):
        sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
        conn = self.Connection(sock, None)
        response = conn.get('/', {})
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response, (200, 'OK', {}, None))
        self.assertEqual(sock._wfile.getvalue(), b'GET / HTTP/1.1\r\n\r\n')
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)

    def test_head(self):
        sock = MockSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n')
        conn = self.Connection(sock, None)
        response = conn.head('/', {})
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response, (200, 'OK', {'content-length': 17}, None))
        self.assertEqual(sock._wfile.getvalue(), b'HEAD / HTTP/1.1\r\n\r\n')
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)

    def test_delete(self):
        sock = MockSocket(b'HTTP/1.1 200 OK\r\n\r\n')
        conn = self.Connection(sock, None)
        response = conn.delete('/', {})
        self.assertIs(type(response), self.ResponseType)
        self.assertEqual(response, (200, 'OK', {}, None))
        self.assertEqual(sock._wfile.getvalue(), b'DELETE / HTTP/1.1\r\n\r\n')
        del conn
        self.assertEqual(sys.getrefcount(sock), 2)

    def test_get_range(self):
        parts = (
            b'HTTP/1.1 200 OK\r\n',
            b'Content-Length: 3\r\n',
            b'Content-Range: bytes 17-19/21\r\n',
            b'\r\n',
            b'foo',
        )
        data = b''.join(parts)
        sock = MockSocket(data)
        conn = self.Connection(sock, None)
        h = {}
        r = conn.get_range('/', h, 17, 20)
        self.assertIs(type(r), self.ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {
            'content-length': 3,
            'content-range': 'bytes 17-19/21',
        })
        self.assertIs(type(r.headers['content-range']), self.ContentRange)
        self.assertIs(type(r.body), self.Body)
        self.assertEqual(r.body.read(), b'foo')
        self.assertEqual(sock._wfile.getvalue(),
            b'GET / HTTP/1.1\r\nrange: bytes=17-19\r\n\r\n'
        )
        self.assertEqual(h, {'range': 'bytes=17-19'})
        self.assertIs(type(h['range']), self.Range)
        self.assertEqual(sys.getrefcount(h), 2)
        self.assertEqual(sys.getrefcount(h['range']), 2)
        del conn
        del r
        self.assertEqual(sys.getrefcount(sock), 2)

    def test_callables(self):
        items = (
            ('request',   4, 'body'),
            ('put',       3, 'body'),
            ('post',      3, 'body'),
            ('get',       2, 'headers'),
            ('head',      2, 'headers'),
            ('delete',    2, 'headers'),
            ('get_range', 4, 'stop'),
        )
        sock = MockSocket()
        conn = self.Connection(sock, None)
        for (name, number, missing) in items:
            with self.subTest(name=name, number=number):
                self.check_method_args(conn, name, number, missing)
                self.assertIs(conn.closed, False)

class TestConnection_C(TestConnection_Py):
    backend = _base


class TestRouter_Py(BackendTestCase):
    @property
    def Router(self):
        return self.getattr('Router')

    def test_init(self):
        def foo_app(session, request, api):
            return (200, 'OK', {}, b'foo')

        def bar_app(session, request, api):
            return (200, 'OK', {}, b'bar')

        # appmap not a dict instance:
        appmap = [('foo', foo_app), ('bar', bar_app)]
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            'appmap: need a {!r}; got a {!r}: {!r}'.format(dict, list, appmap)
        )

        # appmap has key that is not None or str instance:
        appmap = {'foo': foo_app, 17: bar_app}
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            'appmap key: need a {!r}; got a {!r}: {!r}'.format(
                str, int, 17
            )
        )

        # appmap has value that isn't callable:
        bar_value = random_id()
        appmap = {'foo': foo_app, 'bar': bar_value}
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            "appmap['bar']: value not callable: {!r}".format(bar_value)
        )

        # Empty appmap:
        appmap = {}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap single str key:
        appmap = {'foo': foo_app}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap single key that is None:
        appmap = {None: foo_app}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {None: foo_app})
        
        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap has two keys, both str:
        appmap = {'foo': foo_app, 'bar': bar_app}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap has two keys, one a str and the other None:
        appmap = {'foo': foo_app, None: bar_app}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # Nested appmap:
        key = random_id()
        end = {key: foo_app}
        appmap = end
        for i in range(9):
            appmap = {random_id(): appmap}
        app = self.Router(appmap)
        self.assertIs(app.appmap, appmap)

        # Nested appmap that exceeds max depth:
        appmap = {random_id(): appmap}
        with self.assertRaises(ValueError) as cm:
            self.Router(appmap)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )

        # Recursive appmap
        key1 = random_id()
        key2 = random_id()
        appmap1 = {}
        appmap2 = {}
        appmap1[key1] = appmap2
        appmap2[key2] = appmap1
        with self.assertRaises(ValueError) as cm:
            self.Router(appmap1)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )

    def test_call(self):
        app = self.Router({})
        self.check_method_args(app, '__call__', 3, 'api')

        Request = self.getattr('Request')

        def foo_app(session, request, api):
            return (200, 'OK', {}, b'foo')

        def bar_app(session, request, api):
            return (200, 'OK', {}, b'bar')

        # appmap is empty:
        app = self.Router({})
        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        # One appmap key, a str:
        app = self.Router({'foo': foo_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app})

        r = Request('GET', '/bar', {}, None, [], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app})

        # One appmap key, an empty str:
        app = self.Router({'': foo_app})
        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app})

        r = Request('GET', '/foo/bar', {}, None, ['foo'], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', 'bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app})

        # One appmap key, None:
        app = self.Router({None: foo_app})
        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {None: foo_app})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {None: foo_app})

        # Two appmap keys, both str:
        app = self.Router({'foo': foo_app, 'bar': bar_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        r = Request('GET', '/bar', {}, None, [], ['bar'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, ['bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        r = Request('GET', '/baz', {}, None, [], ['baz'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['baz'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        # Two appmap keys, one str one None:
        app = self.Router({'foo': foo_app, None: bar_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        # Two appmap keys, one empty str one None:
        app = self.Router({'': foo_app, None: bar_app})
        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        r = Request('GET', '/foo/bar', {}, None, ['foo'], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', 'bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        # Nested appmap:
        keys = [random_id() for i in range(10)]
        appmap = foo_app
        for key in keys:
            appmap = {key: appmap}
        keys.reverse()
        uri = '/' + '/'.join(keys)
        app = self.Router(appmap)
        r = self.mkreq('GET', uri)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, keys)
        self.assertEqual(r.path, [])
        for k in r.mount:
            self.assertEqual(sys.getrefcount(k), 3)
        del app
        for key in keys:
            self.assertEqual(sys.getrefcount(appmap), 2)
            self.assertEqual(sys.getrefcount(key), 4)
            appmap = appmap[key]
            self.assertEqual(sys.getrefcount(key), 3)

        # Nested appmap, exceeds ROUTER_MAX_DEPTH:
        keys = [random_id() for i in range(10)]
        appmap = None
        for key in keys:
            if appmap is None:
                last = appmap = {key: foo_app}
            else:
                appmap = {key: appmap}
        keys.reverse()
        uri = '/' + '/'.join(keys)
        app = self.Router(appmap)
        r = self.mkreq('GET', uri)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, keys)
        self.assertEqual(r.path, [])
        for k in r.mount:
            self.assertEqual(sys.getrefcount(k), 3)
        keys.append(random_id())
        last[keys[-2]] = {keys[-1]: foo_app}
        uri = '/' + '/'.join(keys)
        r = self.mkreq('GET', uri)
        with self.assertRaises(ValueError) as cm:
            app(None, r, None)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )
        self.assertEqual(r.mount, keys[:-1])
        self.assertEqual(r.path, keys[-1:])
        del last
        del app
        for key in keys:
            self.assertEqual(sys.getrefcount(appmap), 2)
            self.assertEqual(sys.getrefcount(key), 4)
            appmap = appmap[key]
            self.assertEqual(sys.getrefcount(key), 3)

        # Recursive appmap
        key1 = random_id()
        key2 = random_id()
        uri = '/' + '/'.join([key1, key2] * 5)
        appmap1 = {}
        app = self.Router(appmap1)
        appmap2 = {}
        appmap1[key1] = appmap2
        appmap2[key2] = appmap1
        r = self.mkreq('GET', uri)
        with self.assertRaises(ValueError) as cm:
            app(None, r, None)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )

class TestRouter_C(TestRouter_Py):
    backend = _base


class TestProxyApp_Py(BackendTestCase):
    @property
    def ProxyApp(self):
        return self.getattr('ProxyApp')

    def test_init(self):
        client = random_id()
        self.assertEqual(sys.getrefcount(client), 2)
        app = self.ProxyApp(client)
        self.assertEqual(sys.getrefcount(client), 3)
        self.assertIs(type(app), self.ProxyApp)
        self.assertIs(app.client, client)
        self.assertEqual(app.key, 'conn')
        del app
        self.assertEqual(sys.getrefcount(client), 2)

        key = random_id()
        self.assertEqual(sys.getrefcount(key), 2)
        app = self.ProxyApp(client, key)
        self.assertEqual(sys.getrefcount(client), 3)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertIs(type(app), self.ProxyApp)
        self.assertIs(app.client, client)
        self.assertIs(app.key, key)
        del app
        self.assertEqual(sys.getrefcount(client), 2)
        self.assertEqual(sys.getrefcount(key), 2)

    def test_call(self):
        app = self.ProxyApp(random_id())
        self.check_method_args(app, '__call__', 3, 'api')

class TestProxyApp_C(TestProxyApp_Py):
    backend = _base

