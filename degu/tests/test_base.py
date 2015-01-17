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
from random import SystemRandom

from . import helpers
from .helpers import DummySocket, random_chunks, FuzzTestCase, iter_bad
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


class MockSocket:
    __slots__ = ('_rfile', '_wfile')

    def __init__(self, data):
        self._rfile = io.BytesIO(data)
        self._wfile = io.BytesIO()

    def recv_into(self, buf):
        return self._rfile.readinto(buf)

    def send(self, data):
        return self._wfile.write(data)


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

    def test__MAX_HEADER_COUNT(self):
        self.assertIsInstance(base._MAX_HEADER_COUNT, int)
        self.assertGreaterEqual(base._MAX_HEADER_COUNT, 5)
        self.assertLessEqual(base._MAX_HEADER_COUNT, 20)

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
        self.assertTrue(issubclass(base.BodiesAPI, tuple))
        self.assertIsInstance(base.bodies, tuple)
        self.assertIsInstance(base.bodies, base.BodiesAPI)

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
    def test__read_response_preamble_p(self):
        self.fuzz(_basepy._read_response_preamble)

    def test__read_response_preamble_c(self):
        self.skip_if_no_c_ext()
        self.fuzz(_base._read_response_preamble)

    def test__read_request_preamble_p(self):
        self.fuzz(_basepy._read_request_preamble)

    def test__read_request_preamble_c(self):
        self.skip_if_no_c_ext()
        self.fuzz(_base._read_request_preamble)

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
    def test__makefiles(self):
        sock = DummySocket()
        self.assertEqual(base._makefiles(sock), (sock._rfile, sock._wfile))
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_SIZE}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_SIZE}),
        ])

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

        self.assertEqual(parse_uri(b'/'), {
            'uri': '/',
            'script': [],
            'path': [],
            'query': None,
        })
        self.assertEqual(parse_uri(b'/?'), {
            'uri': '/?',
            'script': [],
            'path': [],
            'query': '',
        })
        self.assertEqual(parse_uri(b'/?q'), {
            'uri': '/?q',
            'script': [],
            'path': [],
            'query': 'q',
        })

        self.assertEqual(parse_uri(b'/foo'), {
            'uri': '/foo',
            'script': [],
            'path': ['foo'],
            'query': None,
        })
        self.assertEqual(parse_uri(b'/foo?'), {
            'uri': '/foo?',
            'script': [],
            'path': ['foo'],
            'query': '',
        })
        self.assertEqual(parse_uri(b'/foo?q'), {
            'uri': '/foo?q',
            'script': [],
            'path': ['foo'],
            'query': 'q',
        })

        self.assertEqual(parse_uri(b'/foo/'), {
            'uri': '/foo/',
            'script': [],
            'path': ['foo', ''],
            'query': None,
        })
        self.assertEqual(parse_uri(b'/foo/?'), {
            'uri': '/foo/?',
            'script': [],
            'path': ['foo', ''],
            'query': '',
        })
        self.assertEqual(parse_uri(b'/foo/?q'), {
            'uri': '/foo/?q',
            'script': [],
            'path': ['foo', ''],
            'query': 'q',
        })

        self.assertEqual(parse_uri(b'/foo/bar'), {
            'uri': '/foo/bar',
            'script': [],
            'path': ['foo', 'bar'],
            'query': None,
        })
        self.assertEqual(parse_uri(b'/foo/bar?'), {
            'uri': '/foo/bar?',
            'script': [],
            'path': ['foo', 'bar'],
            'query': '',
        })
        self.assertEqual(parse_uri(b'/foo/?q'), {
            'uri': '/foo/?q',
            'script': [],
            'path': ['foo', ''],
            'query': 'q',
        })

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
        good_uri = ('/foo', '/?stuff=junk', '/foo/bar/', '/foo/bar?stuff=junk')

        # Test all good methods:
        for method in GOOD_METHODS:
            good = '{} / HTTP/1.1'.format(method).encode()
            self.assertEqual(parse_request_line(good), (method, '/'))
            for i in range(len(good)):
                bad = bytearray(good)
                del bad[i]
                with self.assertRaises(ValueError):
                    parse_request_line(bytes(bad))
                for j in range(256):
                    if good[i] == j:
                        continue
                    bad = bytearray(good)
                    bad[i] = j
                    with self.assertRaises(ValueError):
                        parse_request_line(bytes(bad))
            for uri in good_uri:
                good2 = '{} {} HTTP/1.1'.format(method, uri).encode()
                self.assertEqual(parse_request_line(good2), (method, uri))

        # Pre-generated bad method permutations:
        for uri in good_uri:
            tail = ' {} HTTP/1.1'.format(uri).encode()
            for method in BAD_METHODS:
                bad = method + tail
                with self.assertRaises(ValueError):
                    parse_request_line(bad)

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

        for good in (b'0', b'1', b'9', b'11', b'99', b'9007199254740992'):
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

    def check_format_request_preamble(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_request_preamble()
        with self.assertRaises(TypeError):
            backend.format_request_preamble('GET')
        with self.assertRaises(TypeError):
            backend.format_request_preamble('GET', '/foo')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_request_preamble('GET', '/foo', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_request_preamble('GET', '/foo', {}),
            b'GET /foo HTTP/1.1\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_request_preamble('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_request_preamble('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_request_preamble('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_request_preamble('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_request_preamble('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_request_preamble('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_request_preamble_py(self):
        self.check_format_request_preamble(_basepy)

    def test_format_request_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check_format_request_preamble(_base)

    def check_format_response_preamble(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_response_preamble()
        with self.assertRaises(TypeError):
            backend.format_response_preamble(200)
        with self.assertRaises(TypeError):
            backend.format_response_preamble(200, 'OK')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_response_preamble('200', 'OK', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', {}),
            b'HTTP/1.1 200 OK\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_response_preamble(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_response_preamble_py(self):
        self.check_format_response_preamble(_basepy)

    def test_format_response_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check_format_response_preamble(_base)

    def check_parse_preamble(self, backend):
        self.assertEqual(backend.parse_preamble(b'Foo'), ('Foo', {}))
        parse_preamble = backend.parse_preamble

        self.assertEqual(backend.parse_preamble(b'Foo\r\nBar: Baz'),
            ('Foo', {'bar': 'Baz'})
        )
        self.assertEqual(backend.parse_preamble(b'Foo\r\nContent-Length: 42'),
            ('Foo', {'content-length': 42})
        )
        self.assertEqual(
            backend.parse_preamble(b'Foo\r\nTransfer-Encoding: chunked'),
            ('Foo', {'transfer-encoding': 'chunked'})
        )

        # Bad bytes in first line:
        with self.assertRaises(ValueError) as cm:
            backend.parse_preamble(b'Foo\x00\r\nBar: Baz')
        self.assertEqual(str(cm.exception),
            "bad bytes in first line: b'Foo\\x00'"
        )

        # Bad bytes in header name:
        with self.assertRaises(ValueError) as cm:
            backend.parse_preamble(b'Foo\r\nBar\x00: Baz')
        self.assertEqual(str(cm.exception),
            "bad bytes in header name: b'Bar\\x00'"
        )

        # Bad bytes in header value:
        with self.assertRaises(ValueError) as cm:
            backend.parse_preamble(b'Foo\r\nBar: Baz\x00')
        self.assertEqual(str(cm.exception),
            "bad bytes in header value: b'Baz\\x00'"
        )

        # content-length larger than 9007199254740992:
        value = 9007199254740992
        for gv in (0, 17, value, value - 1, value - 17):
            buf = 'GET / HTTP/1.1\r\nContent-Length: {:d}'.format(gv).encode()
            self.assertEqual(parse_preamble(buf),
                ('GET / HTTP/1.1', {'content-length': gv})
            )
        with self.assertRaises(ValueError) as cm:
            parse_preamble(b'GET / HTTP/1.1\r\nContent-Length: 09007199254740992')
        self.assertEqual(str(cm.exception),
            "content-length too long: b'0900719925474099'..."
        )
        for i in range(1, 101):
            bv = value + i
            buf = 'GET / HTTP/1.1\r\nContent-Length: {:d}'.format(bv).encode()
            with self.assertRaises(ValueError) as cm:
                backend.parse_preamble(buf)
            self.assertEqual(str(cm.exception),
                'content-length value too large: {:d}'.format(bv)
            )
        buf = b'GET / HTTP/1.1\r\nContent-Length: 9999999999999999'
        with self.assertRaises(ValueError) as cm:
            backend.parse_preamble(buf)
        self.assertEqual(str(cm.exception),
            'content-length value too large: 9999999999999999'
        )

    def test_parse_preamble_p(self):
        self.check_parse_preamble(_basepy)

    def test_parse_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_preamble(_base)

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

    def test_len(self):
        for content_length in (0, 17, 27, 37):
            body = base.Body(io.BytesIO(), content_length)
        self.assertEqual(len(body), content_length)

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

    def test_len(self):
        for content_length in (0, 17, 27, 37):
            body = base.BodyIter([], content_length)
        self.assertEqual(len(body), content_length)

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


class TestReader_Py(TestCase):
    backend = _basepy

    @property
    def Reader(self):
        return self.backend.Reader

    @property
    def EmptyPreambleError(self):
        return self.backend.EmptyPreambleError

    def new(self, data=b''):
        sock = MockSocket(data)
        reader = self.Reader(sock, base.bodies)
        return (sock, reader)

    def test_init(self):
        (sock, reader) = self.new()
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.avail(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

    def test_read_raw_preamble(self):
        (sock, reader) = self.new()
        with self.assertRaises(self.EmptyPreambleError) as cm:
            reader.read_raw_preamble()
        self.assertEqual(str(cm.exception), 'HTTP preamble is empty')

        bad_ones = (
            b'GET / HTTP/1.1',
            b'GET / HTTP/1.1Content-Length: 17',
            b'GET / HTTP/1.1\r\n',
            b'GET / HTTP/1.1\r\n\r',
            b'GET / HTTP/1.1\r\nContent-Length: 17',
            b'GET / HTTP/1.1\r\nContent-Length: 17\r\n',
            b'GET / HTTP/1.1\r\nContent-Length: 17\r\n\r',
        )
        for bad in bad_ones:
            (sock, reader) = self.new(bad)
            with self.assertRaises(ValueError) as cm:
                reader.read_raw_preamble()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}'.format(b'\r\n\r\n', bad)
            )
            self.assertEqual(sock._rfile.tell(), len(bad))
            self.assertEqual(reader.rawtell(), len(bad))
            self.assertEqual(reader.avail(), len(bad))
            self.assertEqual(reader.tell(), 0)

        good_ones = (
            b'GET / HTTP/1.1\r\n\r\n',
            b'GET / HTTP/1.1\r\nContent-Length: 17\r\n\r\n',
            b'HTTP/1.1 200 OK\r\n\r\n',
            b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n',
        )
        for good in good_ones:
            (sock, reader) = self.new(good)
            self.assertEqual(reader.read_raw_preamble(), good[0:-4])
            self.assertEqual(sock._rfile.tell(), len(good))
            self.assertEqual(reader.rawtell(), len(good))
            self.assertEqual(reader.avail(), 0)
            self.assertEqual(reader.tell(), len(good))

    def test_read(self):
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.read(-1)
        self.assertEqual(str(cm.exception), 'need size >= 0; got -1')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.avail(), 0)

        self.assertEqual(reader.read(0), b'')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.avail(), 0)

        ret = reader.read_raw_preamble()
        self.assertEqual(ret, b'GET / HTTP/1.1')
        self.assertEqual(sock._rfile.tell(), len(data))
        self.assertEqual(reader.rawtell(), len(data))
        self.assertEqual(reader.tell(), len(ret) + 4)
        self.assertEqual(reader.avail(), len(data) - len(ret) - 4)
        self.assertEqual(sock._rfile.read(), b'')

        self.assertEqual(reader.read(1000), b'Hello naughty nurse!')
        self.assertEqual(sock._rfile.tell(), len(data))
        self.assertEqual(reader.rawtell(), len(data))
        self.assertEqual(reader.tell(), len(data))
        self.assertEqual(reader.avail(), 0)
        self.assertEqual(sock._rfile.read(), b'')

        KiB_64  = 2 ** 16
        KiB_32  = 2 ** 15
        KiB_16  = 2 ** 14
        #KiB_8   = 2 ** 13
        data = b''.join([
            b'A' * KiB_16,
            b'B' * KiB_32,
            b'C' * KiB_64,
        ])
        self.assertEqual(len(data), 112 * 1024)
        (sock, reader) = self.new(data)
        self.assertEqual(reader.read(KiB_16), b'A' * KiB_16)
        self.assertEqual(sock._rfile.tell(), KiB_64)
        self.assertEqual(reader.rawtell(), KiB_64)
        self.assertEqual(reader.tell(), KiB_16)
        self.assertEqual(reader.avail(), KiB_64 - KiB_16)

        self.assertEqual(reader.read(KiB_32), b'B' * KiB_32)
        self.assertEqual(sock._rfile.tell(), KiB_64)
        self.assertEqual(reader.rawtell(), KiB_64)
        self.assertEqual(reader.tell(), KiB_16 + KiB_32)
        self.assertEqual(reader.avail(), KiB_16)

        self.assertEqual(reader.read(KiB_64), b'C' * KiB_64)
        self.assertEqual(sock._rfile.tell(), len(data))
        self.assertEqual(reader.rawtell(), len(data))
        self.assertEqual(reader.tell(), len(data))
        self.assertEqual(reader.avail(), 0)


class TestReader_C(TestReader_Py):
    backend = _base

    def setUp(self):
        if self.backend is None:
            self.skipTest('cannot import `degu._base` C extension')

    def test_read_request(self):
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'
        (sock, reader) = self.new(data)
        self.assertEqual(reader.read_request(),
            {
                'method': 'GET',
                'uri': '/',
                'script': [],
                'path': [],
                'query': None,
                'headers': {},
            }
        )
        
