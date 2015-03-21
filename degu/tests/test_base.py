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
Unit tests for the `degu.base` module`
"""

from unittest import TestCase
import os
import io
import sys
from random import SystemRandom
import socket

from . import helpers
from .helpers import DummySocket, random_chunks, FuzzTestCase, iter_bad, MockSocket
from degu.sslhelpers import random_id
from degu.base import _MAX_LINE_SIZE
from degu import base, _basepy


# True if the C extension is available
try:
    from degu import _base
    C_EXT_AVAIL = True
except ImportError:
    _base = None
    C_EXT_AVAIL = False


random = SystemRandom()


CRLF = b'\r\n'
TERM = CRLF * 2
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


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
    'HEAD',
    'POST',
    'PUT',
    'DELETE',
)
_functions = (_permute_remove, _permute_replace, _permute_insert)
BAD_METHODS = [
    b'',
    b'TRACE',
    b'OPTIONS',
    b'CONNECT',
    b'PATCH',
]
BAD_METHODS.extend(m.encode().lower() for m in GOOD_METHODS)
for func in _functions:
    for m in GOOD_METHODS:
        BAD_METHODS.extend(func(m.encode()))
BAD_METHODS = tuple(sorted(set(BAD_METHODS)))


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


class AlternatesTestCase(FuzzTestCase):
    def skip_if_no_c_ext(self):
        if not C_EXT_AVAIL:
            self.skipTest('cannot import `degu._base` C extension')


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


class TestRange_Py(BackendTestCase):
    @property
    def Range(self):
        return self.getattr('Range')

    def test_init(self):
        r = self.Range(16, 21)
        self.assertIs(type(r.start), int)
        self.assertIs(type(r.stop), int)
        self.assertEqual(r.start, 16)
        self.assertEqual(r.stop, 21)
        self.assertEqual(repr(r), 'Range(16, 21)')
        self.assertEqual(str(r), 'bytes=16-20')



class TestRange_C(TestRange_Py):
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
    def test_parse_range(self):
        parse_range = self.getattr('parse_range')

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
            suffix = '-'.join([str(start), str(stop - 1)]).encode()
            src = prefix + suffix
            self.assertEqual(parse_range(src), (start, stop))

            for i in range(len(prefix)):
                g = prefix[i]
                bad = bytearray(prefix)
                for b in range(256):
                    bad[i] = b
                    src = bytes(bad) + suffix
                    if g == b:
                        self.assertEqual(parse_range(src), (start, stop))
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
                    self.assertEqual(parse_range(src), (start, stop))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_range(src)
                    self.assertEqual(str(cm.exception),
                        'bad range: {!r}'.format(src)
                    )

    def test_parse_headers(self):
        parse_headers = self.getattr('parse_headers')

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


class TestParsingFunctions_C(TestParsingFunctions_Py):
    backend = _base


class dict_subclass(dict):
    pass

class str_subclass(str):
    pass

class int_subclass(int):
    pass


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

    def test_format_headers(self):
        format_headers = self.getattr('format_headers')

        # Bad headers type:
        bad = [('foo', 'bar')]
        with self.assertRaises(TypeError) as cm:
            format_headers(bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, list, bad)
        )
        bad = dict_subclass({'foo': 'bar'})
        with self.assertRaises(TypeError) as cm:
            format_headers(bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, dict_subclass, bad)
        )

        good_items = (
            None,
            ('content-length', 17),
            ('foo', 'bar'),
        )
        good = dict()
        for item in good_items:
            if item:
                (key, value) = item
                good[key] = value

            # Bad key type:
            headers = {b'foo': 'bar'}
            headers.update(good)
            with self.assertRaises(TypeError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('key', str, bytes, b'foo')
            )
            headers = {str_subclass('foo'): 'bar'}
            headers.update(good)
            with self.assertRaises(TypeError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('key', str, str_subclass, 'foo')
            )

            # key contains non-ascii codepoints:
            headers = {'¡': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: '¡'")
            headers = {'™': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: '™'")

            # key is not lowercase:
            headers = {'Foo': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: 'Foo'")
            headers = {'f\no': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: 'f\\no'")

        self.assertEqual(format_headers({}), '')
        self.assertEqual(format_headers({'foo': 17}), 'foo: 17\r\n')
        self.assertEqual(
            format_headers({'foo': 17, 'bar': 18}),
            'bar: 18\r\nfoo: 17\r\n'
        )
        self.assertEqual(
            format_headers({'foo': '17', 'bar': '18'}),
            'bar: 18\r\nfoo: 17\r\n'
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

    def test_Bodies(self):
        (tup, args) = self.new('Bodies', 4)
        self.assertIs(tup.Body,            args[0])
        self.assertIs(tup.BodyIter,        args[1])
        self.assertIs(tup.ChunkedBody,     args[2])
        self.assertIs(tup.ChunkedBodyIter, args[3])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)

    def test_Request(self):
        (tup, args) = self.new('Request', 8)
        self.assertIs(tup.method,  args[0])
        self.assertIs(tup.uri,     args[1])
        self.assertIs(tup.script,  args[2])
        self.assertIs(tup.path,    args[3])
        self.assertIs(tup.query,   args[4])
        self.assertIs(tup.headers, args[5])
        self.assertIs(tup.range,   args[6])
        self.assertIs(tup.body,    args[7])
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


MiB = 1024 * 1024

class TestConstants(TestCase):
    def check_power_of_two(self, name, size):
        self.assertIsInstance(size, int, name)
        self.assertGreaterEqual(size, 1024, name)
        self.assertLessEqual(size, MiB * 32, name)
        self.assertFalse(size & (size - 1),
            '({}) {:d} is not a power of 2'.format(name, size)
        )

    def check_size_constant(self, name, min_size=4096, max_size=16777216):
        self.check_power_of_two('min_size', min_size)
        self.check_power_of_two('max_size', max_size)
        self.assertEqual(name[-5:], '_SIZE', name)
        self.assertTrue(name.isupper(), '{!r} not uppercase'.format(name))
        size = getattr(base, name)
        self.check_power_of_two(name, size)
        self.assertGreaterEqual(size, min_size, name)
        self.assertLessEqual(size, max_size, name)

    def test__MAX_LINE_SIZE(self):
        self.assertIsInstance(base._MAX_LINE_SIZE, int)
        self.assertGreaterEqual(base._MAX_LINE_SIZE, 1024)
        self.assertEqual(base._MAX_LINE_SIZE % 1024, 0)
        self.assertLessEqual(base._MAX_LINE_SIZE, 8192)

    def test_STREAM_BUFFER_SIZE(self):
        self.assertIsInstance(base.STREAM_BUFFER_SIZE, int)
        self.assertEqual(base.STREAM_BUFFER_SIZE % 4096, 0)
        self.assertGreaterEqual(base.STREAM_BUFFER_SIZE, 4096)

    def test_MAX_READ_SIZE(self):
        self.check_size_constant('MAX_READ_SIZE')

    def test_MAX_CHUNK_SIZE(self):
        self.check_size_constant('MAX_CHUNK_SIZE')

    def test_IO_SIZE(self):
        self.check_size_constant('IO_SIZE')

    def test_bodies(self):
        self.assertIsInstance(base.bodies, tuple)
        self.assertIsInstance(base.bodies, base.BodiesType)

        self.assertIs(base.bodies.Body, base.Body)
        self.assertIs(base.bodies.BodyIter, base.BodyIter)
        self.assertIs(base.bodies.ChunkedBody, base.ChunkedBody)
        self.assertIs(base.bodies.ChunkedBodyIter, base.ChunkedBodyIter)

        self.assertIs(base.bodies[0], base.Body)
        self.assertIs(base.bodies[1], base.BodyIter)
        self.assertIs(base.bodies[2], base.ChunkedBody)
        self.assertIs(base.bodies[3], base.ChunkedBodyIter)

        self.assertEqual(base.bodies,
            (base.Body, base.BodyIter, base.ChunkedBody, base.ChunkedBodyIter)
        )


class TestEmptyPreambleError(TestCase):
    def test_init(self):
        e = base.EmptyPreambleError('stuff and junk')
        self.assertIsInstance(e, Exception)
        self.assertIsInstance(e, ConnectionError)
        self.assertIs(type(e), base.EmptyPreambleError)
        self.assertEqual(str(e), 'stuff and junk')


class FuzzTestFunctions(AlternatesTestCase):
    def test_read_chunk(self):
        self.fuzz(base.read_chunk)


class DummyFile:
    def __init__(self, lines):
        self._lines = lines
        self._calls = []

    def readline(self, size=None):
        self._calls.append(size)
        return self._lines.pop(0)


class DummyWriter:
    def __init__(self):
        self._calls = []

    def write(self, data):
        assert isinstance(data, bytes)
        self._calls.append(('write', data))
        return len(data)

    def flush(self):
        self._calls.append('flush')


class UserBytes(bytes):
    pass


class TestFunctions(AlternatesTestCase):
    def test_makefiles(self):
        sock = DummySocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        (reader, writer) = base._makefiles(sock, base.bodies)
        self.assertIsInstance(reader, base.Reader)
        self.assertIsInstance(writer, base.Writer)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 6)
        del reader
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 4)
        del writer
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 2)

    def check_parse_method(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_method = backend.parse_method

        for method in GOOD_METHODS:
            expected = getattr(backend, method)

            # Input is str:
            result = parse_method(method)
            self.assertEqual(result, method)
            self.assertIs(result, expected)

            # Input is bytes:
            result = parse_method(method.encode())
            self.assertEqual(result, method)
            self.assertIs(result, expected)

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

        # Static bad methods:
        bad_methods = (
            'OPTIONS',
            'TRACE',
            'CONNECT',
            'FOO',
            'BAR',
            'COPY',
            'FOUR',
            'SIXSIX',
            'FOOBAR',
            '',
        )
        for bad in bad_methods:
            # Bad str:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

            # Bad bytes:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad.encode())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

        # Pre-generated bad method permutations:
        for bad in BAD_METHODS:
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

    def test_parse_method_py(self):
        self.check_parse_method(_basepy)

    def test_parse_method_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_method(_base)

    def check_parse_uri(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_uri = backend.parse_uri

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

    def test_parse_uri_py(self):
        self.check_parse_uri(_basepy)

    def test_parse_uri_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_uri(_base)

    def check_parse_header_name(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_header_name = backend.parse_header_name

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

    def test_parse_header_name_py(self):
        self.check_parse_header_name(_basepy)

    def test_parse_header_name_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_header_name(_base)

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

    def check_parse_response_line(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_response_line = backend.parse_response_line

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
            self.assertIs(tup[1], backend.OK)

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

    def test_parse_response_line_py(self):
        self.check_parse_response_line(_basepy)

    def test_parse_response_line_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_response_line(_base)

    def check_parse_request_line(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_request_line = backend.parse_request_line
        self.assertEqual(parse_request_line(b'GET / HTTP/1.1'),
            ('GET', '/', [], [], None)
        )

    def test_parse_request_line_py(self):
        self.check_parse_request_line(_basepy)

    def test_parse_request_line_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_request_line(_base)

    def check_parse_content_length(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_content_length = backend.parse_content_length

        # Empty bytes:
        with self.assertRaises(ValueError) as cm:
            parse_content_length(b'')
        self.assertEqual(str(cm.exception), 'content-length is empty')

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
                    self.assertEqual(str(cm.exception), 'content-length is empty')
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
                'content-length has leading zero: {!r}'.format(bad)
            )

        # Netative values and spaces should be reported with the 'bad bytes'
        # ValueError message:
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
                'bad bytes in content-length: {!r}'.format(bad)
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
                    'bad bytes in content-length: {!r}'.format(bad)
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
                    'bad bytes in content-length: {!r}'.format(bad)
                )
        for good in (b'1', b'9', b'11', b'99', b'10', b'90'):
            for also_good in helpers.iter_good(good, b'123456789'):
                self.assertEqual(
                    parse_content_length(also_good),
                    int(also_good)
                )

    def test_parse_content_length_py(self):
        self.check_parse_content_length(_basepy)

    def test_parse_content_length_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_content_length(_base)

        # Compare C to Python implementations with the same random values:
        functions = (_base.parse_content_length, _basepy.parse_content_length)
        for i in range(1000):
            bad = os.urandom(16)
            for func in functions:
                exc = 'bad bytes in content-length: {!r}'.format(bad)
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
            goodval = random.randint(0, 9007199254740992)
            good = str(goodval).encode()
            for func in functions:
                ret = func(good)
                self.assertIsInstance(ret, int)
                self.assertEqual(ret, goodval)

    def check_format_request(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_request()
        with self.assertRaises(TypeError):
            backend.format_request('GET')
        with self.assertRaises(TypeError):
            backend.format_request('GET', '/foo')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_request('GET', '/foo', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_request('GET', '/foo', {}),
            b'GET /foo HTTP/1.1\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_request_py(self):
        self.check_format_request(_basepy)

    def test_format_request_c(self):
        self.skip_if_no_c_ext()
        self.check_format_request(_base)

    def check_format_response(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_response()
        with self.assertRaises(TypeError):
            backend.format_response(200)
        with self.assertRaises(TypeError):
            backend.format_response(200, 'OK')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_response('200', 'OK', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_response(200, 'OK', {}),
            b'HTTP/1.1 200 OK\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_response_py(self):
        self.check_format_response(_basepy)

    def test_format_response_c(self):
        self.skip_if_no_c_ext()
        self.check_format_response(_base)

    def test_read_chunk(self):
        data = (b'D' * 7777)  # Longer than _MAX_LINE_SIZE
        small_data = (b'd' * 6666)  # Still longer than _MAX_LINE_SIZE
        termed = data + b'\r\n'
        self.assertEqual(len(termed), 7779)
        size = b'1e61\r\n'
        size_plus = b'1e61;foo=bar\r\n'

        # No CRLF terminated chunk size line:
        rfile = io.BytesIO(termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'DD'"
        )
        self.assertEqual(rfile.tell(), _MAX_LINE_SIZE)
        self.assertFalse(rfile.closed)

        # Size line has LF but no CR:
        rfile = io.BytesIO(b'1e61\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'1\\n'"
        )
        self.assertEqual(rfile.tell(), 5)
        self.assertFalse(rfile.closed)

        # Totally empty:
        rfile = io.BytesIO(b'')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b''"
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)

        # Size line is property terminated, but empty value:
        rfile = io.BytesIO(b'\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b''"
        )
        self.assertEqual(rfile.tell(), 2)
        self.assertFalse(rfile.closed)

        # Too many b';' is size line:
        rfile = io.BytesIO(b'foo;bar;baz\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size line: b'foo;bar;baz\\r\\n'"
        )
        self.assertEqual(rfile.tell(), 13)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Size isn't a hexidecimal integer:
        rfile = io.BytesIO(b'17.6\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 6)
        self.assertFalse(rfile.closed)
        rfile = io.BytesIO(b'17.6;1e61=bar\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 15)
        self.assertFalse(rfile.closed)

        # Size is negative:
        rfile = io.BytesIO(b'-1\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got -1'.format(base.MAX_CHUNK_SIZE)
        )
        self.assertEqual(rfile.tell(), 4)
        self.assertFalse(rfile.closed)
        rfile = io.BytesIO(b'-1e61;1e61=bar\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got -7777'.format(base.MAX_CHUNK_SIZE)
        )
        self.assertEqual(rfile.tell(), 16)
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_SIZE:
        line = '{:x}\r\n'.format(base.MAX_CHUNK_SIZE + 1)
        rfile = io.BytesIO(line.encode('latin_1') + data)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= 16777216; got 16777217'
        )
        self.assertEqual(rfile.tell(), len(line))
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_SIZE, with extension:
        line = '{:x};foo=bar\r\n'.format(base.MAX_CHUNK_SIZE + 1)
        rfile = io.BytesIO(line.encode('latin_1') + data)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= 16777216; got 16777217'
        )
        self.assertEqual(rfile.tell(), len(line))
        self.assertFalse(rfile.closed)

        # Too few b'=' in chunk extension:
        rfile = io.BytesIO(b'1e61;foo\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need more than 1 value to unpack'
        )
        self.assertEqual(rfile.tell(), 10)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Too many b'=' in chunk extension:
        rfile = io.BytesIO(b'1e61;foo=bar=baz\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 2)'
        )
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Not enough data:
        rfile = io.BytesIO(size + small_data + b'\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'underflow: 6668 < 7777')
        self.assertEqual(rfile.tell(), 6674)
        self.assertFalse(rfile.closed)

        # Data isn't properly terminated:
        rfile = io.BytesIO(size + data + b'TT\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad chunk data termination: b'TT'")
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when it's all good:
        rfile = io.BytesIO(size + termed)
        self.assertEqual(base.read_chunk(rfile), (None, data))
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when size line has extra information:
        rfile = io.BytesIO(size_plus + termed)
        self.assertEqual(base.read_chunk(rfile), (('foo', 'bar'), data))
        self.assertEqual(rfile.tell(), 7793)
        self.assertFalse(rfile.closed)

        # Test max chunk size:
        data = os.urandom(base.MAX_CHUNK_SIZE)
        line = '{:x}\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (None, data))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

        # Again, with extension:
        data = os.urandom(base.MAX_CHUNK_SIZE)
        line = '{:x};foo=bar\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (('foo', 'bar'), data))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

    def test_write_chunk(self):
        # len(data) > MAX_CHUNK_SIZE:
        data = b'D' * (base.MAX_CHUNK_SIZE + 1)
        wfile = io.BytesIO()
        chunk = (None, data)
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, chunk)
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # len(data) > MAX_CHUNK_SIZE, but now with extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), data)
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, chunk)
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # Empty data:
        wfile = io.BytesIO()
        chunk = (None, b'')
        self.assertEqual(base.write_chunk(wfile, chunk), 5)
        self.assertEqual(wfile.getvalue(), b'0\r\n\r\n')

        # Empty data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'),  b'')
        self.assertEqual(base.write_chunk(wfile, chunk), 13)
        self.assertEqual(wfile.getvalue(), b'0;foo=bar\r\n\r\n')

        # Small data:
        wfile = io.BytesIO()
        chunk = (None, b'hello')
        self.assertEqual(base.write_chunk(wfile, chunk), 10)
        self.assertEqual(wfile.getvalue(), b'5\r\nhello\r\n')

        # Small data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), b'hello')
        self.assertEqual(base.write_chunk(wfile, chunk), 18)
        self.assertEqual(wfile.getvalue(), b'5;foo=bar\r\nhello\r\n')

        # Larger data:
        data = b'D' * 7777
        wfile = io.BytesIO()
        chunk = (None, data)
        self.assertEqual(base.write_chunk(wfile, chunk), 7785)
        self.assertEqual(wfile.getvalue(), b'1e61\r\n' + data + b'\r\n')

        # Larger data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), data)
        self.assertEqual(base.write_chunk(wfile, chunk), 7793)
        self.assertEqual(wfile.getvalue(), b'1e61;foo=bar\r\n' + data + b'\r\n')

        # Test random value round-trip with read_chunk():
        for size in range(1776):
            # No extension:
            data = os.urandom(size)
            total = size + len('{:x}'.format(size)) + 4
            fp = io.BytesIO()
            chunk = (None, data)
            self.assertEqual(base.write_chunk(fp, chunk), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), chunk)

            # With extension:
            key = random_id()
            value = random_id()
            total = size + len('{:x};{}={}'.format(size, key, value)) + 4
            fp = io.BytesIO()
            chunk = ((key, value), data)
            self.assertEqual(base.write_chunk(fp, chunk), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), chunk)

        # Make sure we can round-trip MAX_CHUNK_SIZE:
        size = base.MAX_CHUNK_SIZE
        data = os.urandom(size)
        total = size + len('{:x}'.format(size)) + 4
        fp = io.BytesIO()
        chunk = (None, data)
        self.assertEqual(base.write_chunk(fp, chunk), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), chunk)

        # With extension:
        key = random_id()
        value = random_id()
        total = size + len('{:x};{}={}'.format(size, key, value)) + 4
        chunk = ((key, value), data)
        fp = io.BytesIO()
        self.assertEqual(base.write_chunk(fp, chunk), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), chunk)


class TestBody(TestCase):
    def test_init(self):
        rfile = io.BytesIO()

        # Bad content_length type:
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, 17.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, float, 17.0)
        )
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, '17')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, str, '17')
        )

        # Bad content_length value:
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, -1)
        self.assertEqual(str(cm.exception),
            'content_length must be >= 0, got: -1'
        )
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, -17)
        self.assertEqual(str(cm.exception),
            'content_length must be >= 0, got: -17'
        )

        # Bad io_size type:
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, 17, '8192')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('io_size', int, str, '8192')
        )
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, 17, 8192.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('io_size', int, float, 8192.0)
        )

        # io_size too small:
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, 2048)
        self.assertEqual(str(cm.exception),
            'need 4096 <= io_size <= {}; got 2048'.format(base.MAX_READ_SIZE)
        )
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, 4095)
        self.assertEqual(str(cm.exception),
            'need 4096 <= io_size <= {}; got 4095'.format(base.MAX_READ_SIZE)
        )

        # io_size too big:
        size = base.MAX_READ_SIZE * 2
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, size)
        self.assertEqual(str(cm.exception),
            'need 4096 <= io_size <= {}; got {}'.format(base.MAX_READ_SIZE, size)
        )
        size = base.MAX_READ_SIZE + 1
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, size)
        self.assertEqual(str(cm.exception),
            'need 4096 <= io_size <= {}; got {}'.format(base.MAX_READ_SIZE, size)
        )

        # io_size not a power of 2:
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, 40960)
        self.assertEqual(str(cm.exception),
            'io_size must be a power of 2; got 40960'
        )
        # io_size not a power of 2:
        with self.assertRaises(ValueError) as cm:
            base.Body(rfile, 17, 4097)
        self.assertEqual(str(cm.exception),
            'io_size must be a power of 2; got 4097'
        )

        # All good:
        body = base.Body(rfile, 17)
        self.assertIs(body.chunked, False)
        self.assertIs(body.__class__.chunked, False)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.content_length, 17)
        self.assertIs(body.io_size, base.IO_SIZE)
        self.assertIs(body.closed, False)
        self.assertEqual(body._remaining, 17)
        self.assertEqual(repr(body), 'Body(<rfile>, 17)')

        # Now override io_size with a number of good values:
        for size in (4096, 8192, 1048576, base.MAX_READ_SIZE):
            body = base.Body(rfile, 17, size)
            self.assertIs(body.io_size, size)
            body = base.Body(rfile, 17, io_size=size)
            self.assertIs(body.io_size, size)

    def test_read(self):
        data = os.urandom(1776)
        rfile = io.BytesIO(data)
        body = base.Body(rfile, len(data))

        # body.closed is True:
        body.closed = True
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1776)

        # Bad size type:
        body.closed = False
        with self.assertRaises(TypeError) as cm:
            body.read(18.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, float, 18.0)
        )
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1776)
        with self.assertRaises(TypeError) as cm:
            body.read('18')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, str, '18')
        )
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1776)

        # Bad size value:
        with self.assertRaises(ValueError) as cm:
            body.read(-1)
        self.assertEqual(str(cm.exception), 'size must be >= 0; got -1')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1776)
        with self.assertRaises(ValueError) as cm:
            body.read(-18)
        self.assertEqual(str(cm.exception), 'size must be >= 0; got -18')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1776)

        # Now read it all at once:
        self.assertEqual(body.read(), data)
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 0)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')

        # Read it again, this time in parts:
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1776)
        self.assertEqual(body.read(17), data[0:17])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1759)

        self.assertEqual(body.read(18), data[17:35])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 35)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 1741)

        self.assertEqual(body.read(1741), data[35:])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 0)

        self.assertEqual(body.read(1776), b'')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body._remaining, 0)

        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')

        # ValueError (underflow) when trying to read all:
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1800)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1800')
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

        # ValueError (underflow) error when read in parts:
        data = os.urandom(35)
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 37)
        self.assertEqual(body.read(18), data[:18])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(body.content_length, 37)
        self.assertEqual(body._remaining, 19)
        with self.assertRaises(ValueError) as cm:
            body.read(19)
        self.assertEqual(str(cm.exception), 'underflow: 17 < 19')
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

        # Test with empty body:
        rfile = io.BytesIO(os.urandom(21))
        body = base.Body(rfile, 0)
        self.assertEqual(body.read(17), b'')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 0)
        self.assertEqual(body._remaining, 0)
        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')

        # Test with random chunks:
        for i in range(25):
            chunks = random_chunks()
            assert chunks[-1] == b''
            data = b''.join(chunks)
            trailer = os.urandom(17)
            rfile = io.BytesIO(data + trailer)
            body = base.Body(rfile, len(data))
            for chunk in chunks:
                self.assertEqual(body.read(len(chunk)), chunk)
            self.assertIs(body.chunked, False)
            self.assertIs(body.closed, True)
            self.assertEqual(rfile.tell(), len(data))
            self.assertEqual(body.content_length, len(data))
            self.assertEqual(body._remaining, 0)
            with self.assertRaises(ValueError) as cm:
                body.read(17)
            self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
            self.assertEqual(rfile.read(), trailer)

        # Test when read size > MAX_READ_SIZE:
        rfile = io.BytesIO()
        content_length = base.MAX_READ_SIZE + 1
        body = base.Body(rfile, content_length)
        self.assertIs(body.content_length, content_length)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'max read size exceeded: {} > {}'.format(
                content_length, base.MAX_READ_SIZE
            )
        )

    def test_iter(self):
        data = os.urandom(1776)

        # content_length=0
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 0)
        self.assertEqual(list(body), [])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(rfile.read(), data)

        # content_length=69
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 69)
        self.assertEqual(list(body), [data[:69]])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), 69)
        self.assertEqual(rfile.read(), data[69:])

        # content_length=1776
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1776)
        self.assertEqual(list(body), [data])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(rfile.read(), b'')

        # content_length=1777
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1777)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1777')
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

        # Make sure data is read in IO_SIZE chunks:
        data1 = os.urandom(base.IO_SIZE)
        data2 = os.urandom(base.IO_SIZE)
        length = base.IO_SIZE * 2
        rfile = io.BytesIO(data1 + data2)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with smaller final chunk:
        length = base.IO_SIZE * 2 + len(data)
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with length 1 byte less than available:
        length = base.IO_SIZE * 2 + len(data) - 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data[:-1]])
        self.assertEqual(body._remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'Body.closed, already consumed')
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), data[-1:])

        # Again, with length 1 byte *more* than available:
        length = base.IO_SIZE * 2 + len(data) + 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1777')
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)


class TestChunkedBody(TestCase):
    def test_init(self):
        # All good:
        rfile = io.BytesIO()
        body = base.ChunkedBody(rfile)
        self.assertIs(body.chunked, True)
        self.assertIs(body.__class__.chunked, True)
        self.assertIs(body.rfile, rfile)
        self.assertIs(body.closed, False)
        self.assertEqual(repr(body), 'ChunkedBody(<rfile>)')

    def test_readchunk(self):
        chunks = random_chunks()
        self.assertEqual(chunks[-1], b'')
        rfile = io.BytesIO()
        total = sum(base.write_chunk(rfile, (None, data)) for data in chunks)
        self.assertEqual(rfile.tell(), total)
        extra = os.urandom(3469)
        rfile.write(extra)
        rfile.seek(0)

        # Test when closed:
        body = base.ChunkedBody(rfile)
        body.closed = True
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.closed, already consumed'
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(rfile.closed, False)

        # Test when all good:
        body = base.ChunkedBody(rfile)
        for data in chunks:
            self.assertEqual(body.readchunk(), (None, data))
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.closed, already consumed'
        )
        self.assertEqual(rfile.read(), extra)

        # Test when read_chunk() raises an exception, which should close the
        # rfile, but not close the body:
        rfile = io.BytesIO(b'17.6\r\n' + extra)
        body = base.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

    def test_iter(self):
        chunks = random_chunks()
        self.assertEqual(chunks[-1], b'')
        rfile = io.BytesIO()
        total = sum(base.write_chunk(rfile, (None, data)) for data in chunks)
        self.assertEqual(rfile.tell(), total)
        extra = os.urandom(3469)
        rfile.write(extra)
        rfile.seek(0)

        # Test when closed:
        body = base.ChunkedBody(rfile)
        body.closed = True
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'ChunkedBody.closed, already consumed'
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(rfile.closed, False)

        # Test when all good:
        body = base.ChunkedBody(rfile)
        self.assertEqual(list(body), [(None, data) for data in chunks])
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'ChunkedBody.closed, already consumed'
        )
        self.assertEqual(rfile.read(), extra)

        # Test when read_chunk() raises an exception, which should close the
        # rfile, but not close the body:
        rfile = io.BytesIO(b'17.6\r\n' + extra)
        body = base.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

    def test_read(self):
        # Total read size too large:
        chunks = [
            (None, b'A' * base.MAX_READ_SIZE),
            (None, b'B'),
            (None, b''),
        ]
        rfile = io.BytesIO()
        for chunk in chunks:
            base.write_chunk(rfile, chunk)
        rfile.seek(0)
        body = base.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'max read size exceeded: {:d} > {:d}'.format(
                base.MAX_READ_SIZE + 1, base.MAX_READ_SIZE
            )
        )

        # Total read size too large:
        size = base.MAX_READ_SIZE // 8
        chunks = [
            (None, bytes([i]) * size) for i in b'ABCDEFGH'
        ]
        assert len(chunks) == 8
        chunks.extend([(None, b'I'), (None, b'')])
        rfile = io.BytesIO()
        for chunk in chunks:
            base.write_chunk(rfile, chunk)
        rfile.seek(0)
        body = base.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'max read size exceeded: {:d} > {:d}'.format(
                base.MAX_READ_SIZE + 1, base.MAX_READ_SIZE
            )
        )

        # A chunk is larger than MAX_CHUNK_SIZE:
        pretent_max_size = base.MAX_CHUNK_SIZE + 1
        chunks = [
            (None, b'A'),
            (None, b'B' * pretent_max_size),
            (None, b''),
        ]
        rfile = io.BytesIO()
        for chunk in chunks:
            base.write_chunk(rfile, chunk, max_size=pretent_max_size)
        rfile.seek(0)
        body = base.ChunkedBody(rfile)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got {}'.format(
                base.MAX_CHUNK_SIZE, base.MAX_CHUNK_SIZE + 1
            )
        )


class TestBodyIter(TestCase):
    def test_init(self):
        # Good source with bad content_length type:
        with self.assertRaises(TypeError) as cm:
            base.BodyIter([], 17.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, float, 17.0)
        )
        with self.assertRaises(TypeError) as cm:
            base.BodyIter([], '17')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, str, '17')
        )

        # Good source with bad content_length value:
        with self.assertRaises(ValueError) as cm:
            base.BodyIter([], -1)
        self.assertEqual(str(cm.exception),
            'content_length must be >= 0, got: -1'
        )
        with self.assertRaises(ValueError) as cm:
            base.BodyIter([], -17)
        self.assertEqual(str(cm.exception),
            'content_length must be >= 0, got: -17'
        )

        # All good:
        source = []
        body = base.BodyIter(source, 17)
        self.assertIs(body.chunked, False)
        self.assertIs(body.__class__.chunked, False)
        self.assertIs(body.source, source)
        self.assertEqual(body.content_length, 17)
        self.assertIs(body.closed, False)
        self.assertIs(body._started, False)

    def test_write_to(self):
        source = (b'hello', b'naughty', b'nurse')

        # Test when closed:
        body = base.BodyIter(source, 17)
        body.closed = True
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'BodyIter.closed, already consumed')
        self.assertEqual(wfile._calls, [])

        # Test when _started:
        body = base.BodyIter(source, 17)
        body._started = True
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'BodyIter._started')
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, [])

        # Should be closed after calling write_to():
        body = base.BodyIter(source, 17)
        wfile = DummyWriter()
        self.assertEqual(body.write_to(wfile), 17)
        self.assertIs(body._started, True)
        self.assertIs(body.closed, True)
        self.assertEqual(wfile._calls, [
            ('write', b'hello'),
            ('write', b'naughty'),
            ('write', b'nurse'),
            'flush',
        ])
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'BodyIter.closed, already consumed')

        # ValueError should be raised at first item that pushing total above
        # content_length:
        body = base.BodyIter(source, 4)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'overflow: 5 > 4')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, [])

        body = base.BodyIter(source, 5)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'overflow: 12 > 5')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, [('write', b'hello')])

        body = base.BodyIter(source, 12)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'overflow: 17 > 12')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls,
            [('write', b'hello'), ('write', b'naughty')]
        )

        body = base.BodyIter(source, 16)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'overflow: 17 > 16')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls,
            [('write', b'hello'), ('write', b'naughty')]
        )

        # ValueError for underflow should only be raised after all items have
        # been yielded:
        body = base.BodyIter(source, 18)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'underflow: 17 < 18')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls,
            [('write', b'hello'), ('write', b'naughty'), ('write', b'nurse')]
        )

        # Empty data items are fine:
        source = (b'', b'hello', b'', b'naughty', b'', b'nurse', b'')
        body = base.BodyIter(source, 17)
        wfile = DummyWriter()
        self.assertEqual(body.write_to(wfile), 17)
        expected = [('write', data) for data in source]
        expected.append('flush')
        self.assertEqual(wfile._calls, expected)
        self.assertIs(body._started, True)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'BodyIter.closed, already consumed')

        # Test with random data of varying sizes:
        source = [os.urandom(i) for i in range(50)]
        content_length = sum(range(50))
        body = base.BodyIter(source, content_length)
        wfile = DummyWriter()
        self.assertEqual(body.write_to(wfile), content_length)
        expected = [('write', data) for data in source]
        expected.append('flush')
        self.assertEqual(wfile._calls, expected)
        self.assertIs(body._started, True)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'BodyIter.closed, already consumed')


class TestChunkedBodyIter(TestCase):
    def test_init(self):
        source = []
        body = base.ChunkedBodyIter(source)
        self.assertIs(body.chunked, True)
        self.assertIs(body.__class__.chunked, True)
        self.assertIs(body.source, source)
        self.assertIs(body.closed, False)
        self.assertIs(body._started, False)

    def test_write_to(self):
        source = (
            (None, b'hello'),
            (None, b'naughty'),
            (None, b'nurse'),
            (None, b''),
        )

        # Test when closed:
        body = base.ChunkedBodyIter(source)
        body.closed = True
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception),
            'ChunkedBodyIter.closed, already consumed'
        )
        self.assertEqual(wfile._calls, [])

        # Test when _started:
        body = base.ChunkedBodyIter(source)
        body._started = True
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'ChunkedBodyIter._started')
        self.assertEqual(wfile._calls, [])

        # Should close after one call:
        body = base.ChunkedBodyIter(source)
        wfile = DummyWriter()
        self.assertEqual(body.write_to(wfile), 37)
        self.assertEqual(wfile._calls, ['flush',
            ('write', b'5\r\nhello\r\n'), 'flush',
            ('write', b'7\r\nnaughty\r\n'), 'flush',
            ('write', b'5\r\nnurse\r\n'), 'flush',
            ('write', b'0\r\n\r\n'), 'flush',
        ])
        self.assertIs(body._started, True)
        self.assertIs(body.closed, True)
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception),
            'ChunkedBodyIter.closed, already consumed'
        )

        # Should raise a ValueError on an empty source:
        body = base.ChunkedBodyIter([])
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'final chunk data was not empty')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, ['flush'])

        # Should raise ValueError if final chunk isn't empty:
        source = (
            (None, b'hello'),
            (None, b'naughty'),
            (None, b'nurse'),
        )
        body = base.ChunkedBodyIter(source)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'final chunk data was not empty')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, ['flush',
            ('write', b'5\r\nhello\r\n'), 'flush',
            ('write', b'7\r\nnaughty\r\n'), 'flush',
            ('write', b'5\r\nnurse\r\n'), 'flush',
        ])

        # Should raise a ValueError if empty chunk is followed by non-empty:
        source = (
            (None, b'hello'),
            (None, b'naughty'),
            (None, b''),
            (None, b'nurse'),
            (None, b''),
        )
        body = base.ChunkedBodyIter(source)
        wfile = DummyWriter()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), 'non-empty chunk data after empty')
        self.assertIs(body._started, True)
        self.assertIs(body.closed, False)
        self.assertEqual(wfile._calls, ['flush',
            ('write', b'5\r\nhello\r\n'), 'flush',
            ('write', b'7\r\nnaughty\r\n'), 'flush',
            ('write', b'0\r\n\r\n'), 'flush',
        ])

        # Test with random data of varying sizes:
        source = [(None, os.urandom(size)) for size in range(1, 51)]
        random.shuffle(source)
        source.append((None, b''))
        body = base.ChunkedBodyIter(tuple(source))
        wfile = DummyWriter()
        self.assertEqual(body.write_to(wfile), 1565)
        self.assertIs(body._started, True)
        self.assertIs(body.closed, True)
        expected = ['flush']
        for chunk in source:
            expected.extend(
                [('write', base._encode_chunk(chunk)), 'flush']
            )
        self.assertEqual(wfile._calls, expected)



class BadSocket:
    def __init__(self, ret):
        self._ret = ret

    def shutdown(self, how):
        pass

    def recv_into(self, buf):
        if isinstance(self._ret, Exception):
            raise self._ret
        return self._ret


class TestReader_Py(BackendTestCase):
    @property
    def Reader(self):
        return self.backend.Reader

    @property
    def MIN_PREAMBLE(self):
        return self.backend.MIN_PREAMBLE

    @property
    def DEFAULT_PREAMBLE(self):
        return self.backend.DEFAULT_PREAMBLE

    @property
    def MAX_PREAMBLE(self):
        return self.backend.MAX_PREAMBLE

    @property
    def ResponseType(self):
        return self.backend.ResponseType

    @property
    def EmptyPreambleError(self):
        return self.backend.EmptyPreambleError

    def new(self, data=b'', rcvbuf=None):
        sock = MockSocket(data, rcvbuf)
        reader = self.Reader(sock, base.bodies)
        return (sock, reader)

    def test_init(self):
        default = self.DEFAULT_PREAMBLE
        _min = self.MIN_PREAMBLE
        _max = self.MAX_PREAMBLE
        self.assertTrue(_min <= default <= _max)

        sock = MockSocket(b'')
        reader = self.Reader(sock, base.bodies)
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # Test min and max sizes:
        for good in (_min, _max):
            reader = self.Reader(sock, base.bodies, size=good)
            self.assertEqual(reader.expose(), b'\x00' * good)

        # size out of range:
        for bad in (_min - 1, _max + 1):
            with self.assertRaises(ValueError) as cm:
                self.Reader(sock, base.bodies, size=bad)
            self.assertEqual(str(cm.exception),
                'need {} <= size <= {}; got {}'.format(_min, _max, bad)
            )

    def test_del(self):
        sock = MockSocket(b'')
        self.assertEqual(sys.getrefcount(sock), 2)
        bodies = base.bodies
        c1 = sys.getrefcount(bodies)
        c2 = sys.getrefcount(bodies.Body)
        c3 = sys.getrefcount(bodies.ChunkedBody)
        reader = self.Reader(sock, bodies)
        self.assertEqual(sys.getrefcount(sock), 4)
        self.assertEqual(sys.getrefcount(bodies), c1)
        self.assertEqual(sys.getrefcount(bodies.Body), c2 + 1)
        self.assertEqual(sys.getrefcount(bodies.ChunkedBody), c3 + 1)
        del reader
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(bodies), c1)
        self.assertEqual(sys.getrefcount(bodies.Body), c2)
        self.assertEqual(sys.getrefcount(bodies.ChunkedBody), c3)

    def test_close(self):
        (sock, reader) = self.new()
        self.assertIsNone(reader.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])
        self.assertIsNone(reader.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])

    def test_Body(self):
        (sock, reader) = self.new()

        body = reader.Body(0)
        self.assertIsInstance(body, base.bodies.Body)
        self.assertIs(body.rfile, reader)
        self.assertEqual(body.content_length, 0)

        body = reader.Body(17)
        self.assertIsInstance(body, base.bodies.Body)
        self.assertIs(body.rfile, reader)
        self.assertEqual(body.content_length, 17)

    def test_ChunkedBody(self):
        (sock, reader) = self.new()
        body = reader.ChunkedBody()
        self.assertIsInstance(body, base.bodies.ChunkedBody)
        self.assertIs(body.rfile, reader)

    def test_read_until(self):
        default = self.DEFAULT_PREAMBLE
        end = b'\r\n'

        data = os.urandom(2 * default)
        (sock, reader) = self.new(data)

        # len(end) == 0:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(4096, b'')
        self.assertEqual(str(cm.exception), 'end cannot be empty')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < 0:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(-1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got -1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < 1:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(0, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 0'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < len(end):
        with self.assertRaises(ValueError) as cm:
            reader.read_until(1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)
        with self.assertRaises(ValueError) as cm:
            reader.read_until(15, os.urandom(16))
        self.assertEqual(str(cm.exception),
            'need 16 <= size <= {}; got 15'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size > default:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(default + 1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got {}'.format(default, default + 1)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # Both always_drain and strip_end are True:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(17, end, always_drain=True, strip_end=True)
        self.assertEqual(str(cm.exception),
            '`always_drain` and `strip_end` cannot both be True'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # No data:
        (sock, reader) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(4096, end), b'')
        self.assertEqual(sock._recv_into_calls, 1)

        (sock, reader) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(4096, end, always_drain=True), b'')
        self.assertEqual(sock._recv_into_calls, 1)

        (sock, reader) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(4096, end, strip_end=True), b'')
        self.assertEqual(sock._recv_into_calls, 1)

        # Main event:
        part1 = os.urandom(1234)
        part2 = os.urandom(2345)
        end = os.urandom(16)
        data = part1 + end + part2 + end
        size = len(data)

        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(size, end), part1 + end)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(reader.read_until(size, end), part2 + end)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        # always_drain=True:
        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(
            reader.read_until(size, end, always_drain=True),
            part1 + end
        )
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(
            reader.read_until(size, end, always_drain=True),
            part2 + end
        )
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        # strip_end=True:
        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(size, end, strip_end=True), part1)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(reader.read_until(size, end, strip_end=True), part2)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        nope = os.urandom(16)
        marker = os.urandom(16)
        suffix = os.urandom(666)
        for i in range(318):
            prefix = os.urandom(i)
            data = prefix + marker
            total_data = data + suffix
            (sock, reader) = self.new(total_data, 333)
            self.assertEqual(reader.read_until(333, marker), data)
            self.assertEqual(reader.peek(-1), total_data[i+16:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), i + 16)

            (sock, reader) = self.new(total_data, 333)
            with self.assertRaises(ValueError) as cm:
                reader.read_until(333, nope)
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(nope, total_data[:32])
            )
            self.assertEqual(reader.peek(-1), total_data[:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), 0)
            self.assertEqual(reader.read_until(333, marker), data)
            self.assertEqual(reader.peek(-1), total_data[i+16:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), i + 16)

            (sock, reader) = self.new(total_data, 333)
            self.assertEqual(
                reader.read_until(333, nope, always_drain=True),
                total_data[:333]
            )
            self.assertEqual(reader.peek(-1), b'')
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), 333)

    def test_readline(self):
        size = self.DEFAULT_PREAMBLE
        (sock, reader) = self.new()
        self.assertEqual(reader.readline(size), b'')
        data = b'D' * size
        (sock, reader) = self.new(data)
        self.assertEqual(reader.readline(size), data)

    def check_read_request(self, rcvbuf):
        # Empty preamble:
        (sock, reader) = self.new(b'', rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            reader.read_request()
        self.assertEqual(str(cm.exception), 'request preamble is empty')

        # Good preamble termination:
        prefix = b'GET / HTTP/1.1'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        data = prefix + term + suffix
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        request = reader.read_request()
        self.assertIsInstance(request, self.getattr('RequestType'))
        self.assertEqual(request, ('GET', '/', [], [], None, {}, None, None))

        # Bad preamble termination:
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_request()
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )
            self.assertEqual(reader.rawtell(), len(data))
            self.assertEqual(reader.tell(), 0)

        # Request line too short
        for i in range(len(prefix)):
            bad = bytearray(prefix)
            del bad[i]
            bad = bytes(bad)
            data = bad + term + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_request()
            self.assertEqual(str(cm.exception),
                'request line too short: {!r}'.format(bad)
            )

        # With Range header:
        data = b'GET / HTTP/1.1\r\nRange: bytes=0-0\r\n\r\n'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        request = reader.read_request()
        self.assertIsInstance(request, self.getattr('RequestType'))
        self.assertEqual(request,
            ('GET', '/', [], [], None, {'range': 'bytes=0-0'}, (0, 1), None)
        )

    def test_read_request(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_request(rcvbuf)

    def check_read_response(self, rcvbuf):
        # Bad method:
        for method in BAD_METHODS:
            (sock, reader) = self.new()
            with self.assertRaises(ValueError) as cm:
                reader.read_response(method)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method)
            )

        # Test when exact b'\r\n\r\n' preamble termination is missing:
        data = b'HTTP/1.1 200 OK\n\r\nhello, world'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        with self.assertRaises(ValueError) as cm:
            reader.read_response('GET')
        self.assertEqual(str(cm.exception),
            '{!r} not found in {!r}...'.format(b'\r\n\r\n', data)
        )
        if rcvbuf is None:
            self.assertEqual(sock._recv_into_calls, 2)
        else:
            self.assertEqual(sock._recv_into_calls, len(data) // rcvbuf + 1)

        prefix = b'HTTP/1.1 200 OK'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_response('GET')
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )

        (sock, reader) = self.new(rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            reader.read_response('GET')
        self.assertEqual(str(cm.exception), 'response preamble is empty')
        if rcvbuf is None:
            self.assertEqual(sock._recv_into_calls, 1)
        else:
            self.assertEqual(sock._recv_into_calls, 1)

        data = b'HTTP/1.1 200 OK\r\n\r\nHello naughty nurse!'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        response = reader.read_response('GET')
        self.assertIsInstance(response, self.ResponseType)
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
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_response('GET')
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
                (sock, reader) = self.new(data, rcvbuf=rcvbuf)
                with self.assertRaises(ValueError) as cm:
                    reader.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad response line: {!r}'.format(bad)
                )

        template = 'HTTP/1.1 {:03d} OK\r\n\r\nHello naughty nurse!'
        for status in range(1000):
            data = template.format(status).encode()
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            if 100 <= status <= 599:
                response = reader.read_response('GET')
                self.assertIsInstance(response, self.ResponseType)
                self.assertEqual(response.status, status)
                self.assertEqual(response.reason, 'OK')
                self.assertEqual(response.headers, {})
                self.assertIs(response.body, None)
                self.assertEqual(response, (status, 'OK', {}, None))
            else:
                with self.assertRaises(ValueError) as cm:
                    reader.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad status: {!r}'.format('{:03d}'.format(status).encode())
                )

    def test_read_response(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_response(rcvbuf)

    def test_read(self):
        default = self.DEFAULT_PREAMBLE
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.read(-1)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 16777216; got -1'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.read(16777217)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 16777216; got 16777217'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        self.assertEqual(reader.read(0), b'')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        A = b'A' * 1024
        B = b'B' * default
        C = b'C' * 512
        D = b'D' * (default + 1)
        (sock, reader) = self.new(A + B + C + D)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        (sock, reader) = self.new(A + B + C + D, 3)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        (sock, reader) = self.new(A + B + C + D, 1)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        badsocket = BadSocket(17.0)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(TypeError) as cm:
            reader.read(12345)
        self.assertEqual(str(cm.exception),
            "need a <class 'int'>; recv_into() returned a <class 'float'>: 17.0"
        )

        smax = sys.maxsize * 2 + 1
        badsocket = BadSocket(smax + 1)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OverflowError) as cm:
            reader.read(12345)
        self.assertEqual(str(cm.exception),
            'Python int too large to convert to C size_t'
        )

        badsocket = BadSocket(-1)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OverflowError) as cm:
            reader.read(12345)
        self.assertEqual(str(cm.exception),
            "can't convert negative value to size_t"
        )

        badsocket = BadSocket(12346)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OSError) as cm:
            reader.read(12345)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 12345; recv_into() returned 12346'
        )

        marker = random_id()
        exc = ValueError(marker)
        badsocket = BadSocket(exc)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(ValueError) as cm:
            reader.read(12345)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)

    def test_readinto(self):
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(bytearray(0))
        self.assertEqual(str(cm.exception),
            'need 1 <= len(buf) <= 16777216; got 0'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        (sock, reader) = self.new(data)
        buf = bytearray(16777217)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(buf)
        self.assertEqual(str(cm.exception),
            'need 1 <= len(buf) <= 16777216; got 16777217'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(buf, b'\x00' * 16777217)

        (sock, reader) = self.new(data)
        buf = bytearray(1)
        self.assertEqual(reader.readinto(buf), 1)
        self.assertEqual(buf, b'G')

        (sock, reader) = self.new(data)
        buf = bytearray(16777216)
        self.assertEqual(reader.readinto(buf), len(data))
        self.assertEqual(buf, data + (b'\x00' * (len(buf) - len(data))))

        dst = memoryview(bytearray(12345))
        badsocket = BadSocket(17.0)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(TypeError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            "need a <class 'int'>; recv_into() returned a <class 'float'>: 17.0"
        )

        smax = sys.maxsize * 2 + 1
        badsocket = BadSocket(smax + 1)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OverflowError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            'Python int too large to convert to C size_t'
        )

        badsocket = BadSocket(-1)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OverflowError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            "can't convert negative value to size_t"
        )

        badsocket = BadSocket(12346)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OSError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 12345; recv_into() returned 12346'
        )

        badsocket = BadSocket(smax)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(OSError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 12345; recv_into() returned {!r}'.format(smax)
        )

        marker = random_id()
        exc = ValueError(marker)
        badsocket = BadSocket(exc)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(dst)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)


class TestReader_C(TestReader_Py):
    backend = _base


################################################################################
# Writer:



class WSocket:
    __slots__ = ('_ret', '_fp', '_calls')

    def __init__(self, **ret):
        self._ret = ret
        self._fp = io.BytesIO()
        self._calls = []

    def _return_or_raise(self, key, default):
        ret = self._ret.get(key, default)
        if isinstance(ret, Exception):
            raise ret
        return ret

    def shutdown(self, how):
        self._calls.append(('shutdown', how))
        return None

    def send(self, buf):
        assert isinstance(buf, memoryview)
        self._calls.append(('send', buf.tobytes()))
        size = self._fp.write(buf)
        return  self._return_or_raise('send', size)


class TestWriter_Py(BackendTestCase):
    @property
    def Writer(self):
        return self.getattr('Writer')

    def test_init(self):
        sock = WSocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        bodies = base.bodies
        bcount = sys.getrefcount(bodies)
        counts = tuple(sys.getrefcount(b) for b in bodies)

        writer = self.Writer(sock, bodies)
        self.assertEqual(sys.getrefcount(sock), 4)
        self.assertEqual(sys.getrefcount(bodies), bcount)
        self.assertEqual(tuple(sys.getrefcount(b) for b in bodies),
            tuple(c + 1 for c in counts)
        )

        del writer
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(bodies), bcount)
        self.assertEqual(tuple(sys.getrefcount(b) for b in bodies), counts)

    def test_close(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)
        self.assertIsNone(writer.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])
        self.assertIsNone(writer.close())
        self.assertEqual(sock._calls, [('shutdown', socket.SHUT_RDWR)])

    def test_tell(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)
        tell = writer.tell()
        self.assertIsInstance(tell, int)
        self.assertEqual(tell, 0)
        self.assertEqual(sock._calls, [])

    def test_write(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)

        data1 = os.urandom(17)
        self.assertEqual(writer.write(data1), 17)
        self.assertEqual(writer.tell(), 17)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

        data2 = os.urandom(18)
        self.assertEqual(writer.write(data2), 18)
        self.assertEqual(writer.tell(), 35)
        self.assertEqual(sock._fp.getvalue(), data1 + data2)
        self.assertEqual(sock._calls, [('send', data1), ('send', data2)])

        marker = random_id()
        exc = ValueError(marker)
        sock = WSocket(send=exc)
        writer = self.Writer(sock, base.bodies)
        with self.assertRaises(ValueError) as cm:
            writer.write(data1)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

        # sock.send() doesn't return an int:
        for bad in (17.0, int_subclass(17)):
            self.assertEqual(bad, 17)
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(TypeError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                'need a {!r}; send() returned a {!r}: {!r}'.format(
                    int, type(bad), bad
                )
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        # sock.send() returns a negative int
        smin = -sys.maxsize - 1
        for bad in (smin - 1, smin, smin + 1, -2, -1):
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(OverflowError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                "can't convert negative value to size_t"
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        # sock.send() returns an int > sys.maxsize:
        smax = sys.maxsize * 2 + 1
        for bad in (smax + 1, smax + 2, smax + 3): 
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(OverflowError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                'Python int too large to convert to C size_t'
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        # soct.send() size > len(buf):
        for bad in (18, 19, smax - 2, smax - 1, smax):
            self.assertGreater(bad, 17)
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(OSError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 17; send() returned {!r}'.format(bad)
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        sock = WSocket(send=0)
        writer = self.Writer(sock, base.bodies)
        with self.assertRaises(OSError) as cm:
            writer.write(data1)
        self.assertEqual(str(cm.exception), 'expected 17; send() returned 0')
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

    def test_flush(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)
        self.assertIsNone(writer.flush())
        self.assertEqual(sock._calls, [])

    def test_write_output(self):
        bodies = base.bodies

        # Empty preamble and empty body:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', None), 0)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sock._fp.getvalue(), b'')

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', b''), 0)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sock._fp.getvalue(), b'')

        # Preamble plus empty body:
        preamble = os.urandom(34)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, None), 34)
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, b''), 34)
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        # body plus empty preamble:
        body = os.urandom(969)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', body), 969)
        self.assertEqual(writer.tell(), 969)
        self.assertEqual(sock._calls, [('send', body)])
        self.assertEqual(sock._fp.getvalue(), body)

        # Body preamble and body are non-empty:
        body = os.urandom(969)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, body), 1003)
        self.assertEqual(writer.tell(), 1003)
        self.assertEqual(sock._calls, [('send', preamble + body)])
        self.assertEqual(sock._fp.getvalue(), preamble + body)

        # no body.write_to attribute:
        class Body1:
            pass

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        body = Body1()
        with self.assertRaises(AttributeError) as cm:
            writer.write_output(preamble, body)
        self.assertEqual(str(cm.exception),
            "'Body1' object has no attribute 'write_to'"
        )
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        # body.write_to isn't callable:
        class Body2:
            write_to = 'nope'

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        body = Body2()
        with self.assertRaises(TypeError) as cm:
            writer.write_output(preamble, body)
        self.assertEqual(str(cm.exception),
            "'str' object is not callable"
        )
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        class Body:
            def __init__(self, *chunks, **ret):
                self._chunks = chunks
                self._ret = ret

            def _return_or_raise(self, key, default):
                value = self._ret.get(key, default)
                if isinstance(value, Exception):
                    raise value
                return value

            def write_to(self, wfile):
                chunks = self._chunks
                self._chunks = None
                total = 0
                write = wfile.write
                total = sum(write(data) for data in chunks)
                return self._return_or_raise('write_to', total)

        data1 = os.urandom(17)
        data2 = os.urandom(18)
        chunks_permutations = (
            tuple(),
            (data1,),
            (data1, data2),
        )

        # body.write_to() raises an exception:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            marker = random_id()
            bad = ValueError(marker)
            body = Body(*chunks, write_to=bad)
            with self.assertRaises(ValueError) as cm:
                writer.write_output(preamble, body)
            self.assertIs(cm.exception, bad)
            self.assertEqual(str(cm.exception), marker)
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                [('send', preamble)] + [('send', d) for d in chunks]
            )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() doesn't return an int:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            body = Body(*chunks, write_to=17.0)
            with self.assertRaises(TypeError) as cm:
                writer.write_output(preamble, body)
            self.assertEqual(str(cm.exception),
                "need a <class 'int'>; write_to() returned a <class 'float'>: 17.0"
            )
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                [('send', preamble)] + [('send', d) for d in chunks]
            )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() returns total < 0:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for bad in (-2**64, -2**64 + 1, -2, -1):
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                with self.assertRaises(OverflowError) as cm:
                    writer.write_output(preamble, body)
                self.assertEqual(str(cm.exception),
                    "can't convert negative int to unsigned"
                )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() returns total >= 2**64:
        tmax = 2**64 - 1
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for bad in (tmax + 1, tmax + 2, tmax + 3):
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                with self.assertRaises(OverflowError) as cm:
                    writer.write_output(preamble, body)
                self.assertEqual(str(cm.exception),
                    'int too big to convert'
                )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() doesn't return the amount written with writer.write():
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for offset in (-2, -1, 1, 2):
                bad = total + offset
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                if bad < 0:
                    with self.assertRaises(OverflowError) as cm:
                        writer.write_output(preamble, body)
                    self.assertEqual(str(cm.exception),
                        "can't convert negative int to unsigned"
                    )
                else:
                    with self.assertRaises(ValueError) as cm:
                        writer.write_output(preamble, body)
                    self.assertEqual(str(cm.exception),
                        '{!r} bytes were written, but write_to() returned {!r}'.format(
                            total, bad
                        )
                    )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # All good:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            body = Body(*chunks)
            self.assertEqual(writer.write_output(preamble, body), total)
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

            p = os.urandom(19)
            b = os.urandom(23)
            c = p + b
            self.assertEqual(writer.write_output(p, b), 42)
            self.assertEqual(writer.tell(), total + 42)
            self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks] + [('send', c)]
                )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks) + c)

    def test_set_default_headers(self):
        bodies = base.bodies
        writer = self.Writer(WSocket(), bodies)

        # body is None:
        headers = {}
        self.assertIsNone(writer.set_default_headers(headers, None))
        self.assertEqual(headers, {})

        headers = {'content-length': 17, 'transfer-encoding': 'chunked'}
        self.assertIsNone(writer.set_default_headers(headers, None))
        self.assertEqual(headers,
            {'content-length': 17, 'transfer-encoding': 'chunked'}
        )

        # bodies with a content-length:
        length_bodies = (
            os.urandom(17),
            bodies.Body(io.BytesIO(), 17),
            bodies.BodyIter([], 17),
        )
        for body in length_bodies:
            headers = {}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'content-length': 17})

            headers = {'content-length': 17}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'content-length': 17})

            headers = {'content-length': 16}
            with self.assertRaises(ValueError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                "'content-length' mismatch: 17 != 16"
            )
            self.assertEqual(headers, {'content-length': 16})

        # chunk-encoded bodies:
        chunked_bodies = (
            bodies.ChunkedBody(io.BytesIO()),
            bodies.ChunkedBodyIter([]),
        )
        for body in chunked_bodies:
            headers = {}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'transfer-encoding': 'chunked'})
    
            headers = {'transfer-encoding': 'chunked'}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'transfer-encoding': 'chunked'})

            headers = {'transfer-encoding': 'clumped'}
            with self.assertRaises(ValueError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                "'transfer-encoding' mismatch: 'chunked' != 'clumped'"
            )

        # bad body types:
        bad_bodies = (
            random_id()[:17],
            io.BytesIO(os.urandom(17)),
        )
        for body in bad_bodies:
            headers = {}
            with self.assertRaises(TypeError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )
            self.assertEqual(headers, {})

            headers = {'content-length': 17, 'transfer-encoding': 'chunked'}
            with self.assertRaises(TypeError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )
            self.assertEqual(headers,
                {'content-length': 17, 'transfer-encoding': 'chunked'}
            )

    def test_write_request(self):
        bodies = self.getattr('Bodies')(
            base.Body,
            base.BodyIter,
            base.ChunkedBody,
            base.ChunkedBodyIter,
        )

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        for method in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:
                writer.write_request(method, '/', {}, None)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method)
            )

        # Empty headers, no body:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            18
        )
        self.assertEqual(headers, {})
        self.assertEqual(writer.tell(), 18)
        self.assertEqual(sock._fp.getvalue(), b'GET / HTTP/1.1\r\n\r\n')

        # One header:
        headers = {'foo': 17}  # Make sure to test with int header value
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            27
        )
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(writer.tell(), 27)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        headers = {'foo': 17, 'bar': 'baz'}
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            37
        )
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(writer.tell(), 37)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        self.assertEqual(
            writer.write_request('GET', '/', headers, b'hello'),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 42)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is bodies.Body:
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = bodies.Body(rfile, 5)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(writer.tell(), 42)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is bodies.BodyIter:
        headers = {}
        body = bodies.BodyIter((b'hell', b'o'), 5)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 42)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = bodies.ChunkedBody(rfile)
        headers = {}
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            61
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(writer.tell(), 61)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.ChunkedBodyIter:
        headers = {}
        body = bodies.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            61
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(writer.tell(), 61)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

    def test_write_response(self):
        bodies = self.getattr('Bodies')(
            base.Body,
            base.BodyIter,
            base.ChunkedBody,
            base.ChunkedBodyIter,
        )

        # Empty headers, no body:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        self.assertEqual(
            writer.write_response(200, 'OK', headers, None),
            19
        )
        self.assertEqual(headers, {})
        self.assertEqual(writer.tell(), 19)
        self.assertEqual(sock._fp.tell(), 19)
        self.assertEqual(sock._fp.getvalue(), b'HTTP/1.1 200 OK\r\n\r\n')

        # One header:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {'foo': 17}  # Make sure to test with int header value
        self.assertEqual(
            writer.write_response(200, 'OK', headers, None),
            28
        )
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(writer.tell(), 28)
        self.assertEqual(sock._fp.tell(), 28)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {'foo': 17, 'bar': 'baz'}
        self.assertEqual(writer.write_response(200, 'OK', headers, None), 38)
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(writer.tell(), 38)
        self.assertEqual(sock._fp.tell(), 38)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        self.assertEqual(
            writer.write_response(200, 'OK', headers, b'hello'),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.BodyIter:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        body = base.BodyIter((b'hell', b'o'), 5)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBodyIter:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        body = base.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            62
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(writer.tell(), 62)
        self.assertEqual(sock._fp.tell(), 62)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.Body:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = base.Body(rfile, 5)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        headers = {}
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = base.ChunkedBody(rfile)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            62
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(writer.tell(), 62)
        self.assertEqual(sock._fp.tell(), 62)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )


class TestWriter_C(TestWriter_Py):
    backend = _base

