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
import itertools

from . import helpers
from .helpers import DummySocket, random_chunks, FuzzTestCase
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
)


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
    def test__read_preamble_p(self):
        self.fuzz(_basepy._read_preamble)

    def test__read_preamble_c(self):
        self.skip_if_no_c_ext()
        self.fuzz(_base._read_preamble)

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
        for method in ('GET', 'PUT', 'POST', 'HEAD', 'DELETE'):
            expected = getattr(backend, method)

            # Input is str:
            result = backend.parse_method(method)
            self.assertEqual(result, method)
            self.assertIs(result, expected)

            # Input is bytes:
            result = backend.parse_method(method.encode())
            self.assertEqual(result, method)
            self.assertIs(result, expected)

            # Lowercase str:
            with self.assertRaises(ValueError) as cm:
                backend.parse_method(method.lower())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

            # Lowercase bytes:
            with self.assertRaises(ValueError) as cm:
                backend.parse_method(method.lower().encode())
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
                backend.parse_method(bad)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

            # Bad bytes:
            with self.assertRaises(ValueError) as cm:
                backend.parse_method(bad.encode())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

        # Random bad bytes:
        for size in range(1, 20):
            for i in range(100):
                bad = os.urandom(size)
                with self.assertRaises(ValueError) as cm:
                    backend.parse_method(bad)
                self.assertEqual(str(cm.exception),
                    'bad HTTP method: {!r}'.format(bad)
                )

    def test_parse_method_p(self):
        self.check_parse_method(_basepy)

    def test_parse_method_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_method(_base)

    def check_format_request_preamble(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError) as cm:
            backend.format_request_preamble()
        with self.assertRaises(TypeError) as cm:
            backend.format_request_preamble('GET')
        with self.assertRaises(TypeError) as cm:
            backend.format_request_preamble('GET', '/foo')

        # Too many arguments:
        with self.assertRaises(TypeError) as cm:
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

    def check_parse_preamble(self, backend):
        self.assertEqual(backend.parse_preamble(b'Foo'), ('Foo', {}))
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

    def test_parse_preamble_p(self):
        self.check_parse_preamble(_basepy)

    def test_parse_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_preamble(_base)

    def check__read_preamble(self, backend):
        self.assertIn(backend, (_basepy, _base))

        # Bad bytes in preamble first line:
        for size in range(1, 8):
            for bad in helpers.iter_bad_values(size):
                data = bad + b'\r\nFoo: Bar\r\nstuff: Junk\r\n\r\n'
                rfile = io.BytesIO(data)
                with self.assertRaises(ValueError) as cm:
                    backend._read_preamble(rfile)
                self.assertEqual(str(cm.exception),
                    'bad bytes in first line: {!r}'.format(bad)
                )
                self.assertEqual(sys.getrefcount(rfile), 2)
                self.assertEqual(rfile.tell(), size + 2)

        # Bad bytes in header name:
        for size in range(1, 8):
            for bad in helpers.iter_bad_keys(size):
                data = b'da first line\r\n' + bad + b': Bar\r\nstuff: Junk\r\n\r\n'
                rfile = io.BytesIO(data)
                with self.assertRaises(ValueError) as cm:
                    backend._read_preamble(rfile)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header name: {!r}'.format(bad)
                )
                self.assertEqual(sys.getrefcount(rfile), 2)
                self.assertEqual(rfile.tell(), size + 22)

        # Bad bytes in header value:
        for size in range(1, 8):
            for bad in helpers.iter_bad_values(size):
                data = b'da first line\r\nFoo: ' + bad + b'\r\nstuff: Junk\r\n\r\n'
                rfile = io.BytesIO(data)
                with self.assertRaises(ValueError) as cm:
                    backend._read_preamble(rfile)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header value: {!r}'.format(bad)
                )
                self.assertEqual(sys.getrefcount(rfile), 2)
                self.assertEqual(rfile.tell(), size + 22)

        # Test number of arguments _read_preamble() takes:
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble()
        self.assertIn(str(cm.exception), {
            '_read_preamble() takes exactly 1 argument (0 given)',
            "_read_preamble() missing 1 required positional argument: 'rfile'"
        })
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble('foo', 'bar')
        self.assertIn(str(cm.exception), {
            '_read_preamble() takes exactly 1 argument (2 given)',
            '_read_preamble() takes 1 positional argument but 2 were given'
        })

        class Bad1:
            pass

        class Bad2:
            readline = 'not callable'

        # rfile has no `readline` attribute:
        rfile = Bad1()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "'Bad1' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline` is not callable:
        rfile = Bad2()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        ##################################################################
        # `rfile.readline()` raises an exception, doesn't return bytes, or
        # returns too many bytes... all on the first line:

        # Exception raised inside call to `rfile.readline()`:
        rfile = DummyFile([])
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line().decode()]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [UserBytes(random_line())]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [b'D' * (backend._MAX_LINE_SIZE - 1) + b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        ##################################################################
        # `rfile.readline()` raises an exception, doesn't return bytes, or
        # returns too many bytes... all on the first *header* line:

        # Exception raised inside call to `rfile.readline()`:
        lines = [random_line()]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line(), random_header_line().decode()]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line(), UserBytes(random_header_line())]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [
            random_line(),
            b'D' * (backend._MAX_LINE_SIZE - 1) + b'\r\n',
        ]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        ##################################################################
        # `rfile.readline()` raises an exception, doesn't return bytes, or
        # returns too many bytes... all on the *last* header line:

        # Exception raised inside call to `rfile.readline()`:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT - 1)
        )
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT - 1)
        )
        lines.append(random_header_line().decode())
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT - 1)
        )
        lines.append(UserBytes(random_header_line()))
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT - 1)
        )
        lines.append(b'D' * (backend._MAX_LINE_SIZE - 1) + b'\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        ##################################################################
        # `rfile.readline()` raises an exception, doesn't return bytes, or
        # returns too many bytes... all on the final CRLF preamble terminating
        # line:

        # Exception raised inside call to `rfile.readline()`:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        lines.append('\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        lines.append(UserBytes(b'\r\n'))
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        lines.append(b'D\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 3 bytes, expected at most 2'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        ###############################
        # Back to testing first line...

        # First line is completely empty, no termination:
        lines = [b'']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(backend.EmptyPreambleError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'HTTP preamble is empty')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # First line badly terminated:
        lines = [b'hello\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b'o\\n'")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # First line is empty yet well terminated:
        lines = [b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'first preamble line is empty')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend._MAX_LINE_SIZE])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        ###############################
        # Back to testing header lines:

        # 1st header line is completely empty, no termination:
        lines = [random_line(), b'']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b''")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # 1st header line is just b'\n':
        lines = [random_line(), b'\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad header line termination: b'\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Valid header but missing \r:
        lines = [random_line(), b'Content-Length: 1776\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad header line termination: b'6\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Header line plus CRLF is fewer than six bytes in length:
        for size in [1, 2, 3]:
            for p in itertools.permutations('k: v', size):
                badline = '{}\r\n'.format(''.join(p)).encode()
                self.assertTrue(3 <= len(badline) < 6)

                # 1st header line is bad:
                lines_1 = [random_line(), badline]

                # 2nd header line is bad:
                lines_2 = [random_line(), random_header_line(), badline]

                # 3rd header line is bad:
                lines_3 = [random_line(), random_header_line(), random_header_line(), badline]

                # Test 'em all:
                for lines in (lines_1, lines_2, lines_3):
                    counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
                    rfile = DummyFile(lines.copy())
                    self.assertEqual(sys.getrefcount(rfile), 2)
                    with self.assertRaises(ValueError) as cm:
                        backend._read_preamble(rfile)
                    self.assertEqual(str(cm.exception),
                        'header line too short: {!r}'.format(badline)
                    )
                    self.assertEqual(rfile._lines, [])
                    self.assertEqual(rfile._calls,
                        [backend._MAX_LINE_SIZE for i in range(len(lines))]
                    )
                    self.assertEqual(sys.getrefcount(rfile), 2)
                    self.assertEqual(counts,
                        tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
                    )

        # Problems in parsing header line:
        for bad in BAD_HEADER_LINES:
            lines = [random_line(), bad]
            counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
            rfile = DummyFile(lines.copy())
            self.assertEqual(sys.getrefcount(rfile), 2)
            with self.assertRaises(ValueError) as cm:
                backend._read_preamble(rfile)
            if len(bad) < 6:
                self.assertEqual(str(cm.exception),
                    'header line too short: {!r}'.format(bad)
                )
            else:
                self.assertEqual(str(cm.exception),
                    'bad header line: {!r}'.format(bad)
                )
            self.assertEqual(rfile._lines, [])
            self.assertEqual(rfile._calls,
                [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
            )
            self.assertEqual(sys.getrefcount(rfile), 2)
            self.assertEqual(counts,
                tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
            )

        # Bad Content-Length:
        lines = [random_line(), b'Content-Length: 16.9\r\n', b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 10: '16.9'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(3)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Negative Content-Length:
        lines = [random_line(), b'Content-Length: -17\r\n', b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'negative content-length: -17')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(3)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Bad Transfer-Encoding:
        lines = [random_line(), b'Transfer-Encoding: clumped\r\n', b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad transfer-encoding: 'clumped'")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(3)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Duplicate header:
        lines = [
            random_line(),
            b'content-type: text/plain\r\n',
            b'Content-Type: text/plain\r\n',
        ]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "duplicate header: b'Content-Type: text/plain\\r\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(3)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Content-Length with Transfer-Encoding:
        lines = [
            random_line(),
            b'Content-Length: 17\r\n',
            b'Transfer-Encoding: chunked\r\n',
            b'\r\n',
        ]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(4)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # content-length with transfer-encoding:
        lines = [
            random_line(),
            b'content-length: 17\r\n',
            b'transfer-encoding: chunked\r\n',
            b'\r\n',
        ]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(4)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Too many headers:
        first_line = random_line()
        header_lines = tuple(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        lines = [first_line]
        lines.extend(header_lines)
        lines.append(b'D\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend._read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(backend._MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile._lines, [])
        calls = [
            backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)
        ]
        calls.append(2)
        self.assertEqual(rfile._calls, calls)
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Test a number of good single values:
        for (header_line, (key, value)) in GOOD_HEADERS:
            first_line = random_line()
            lines = [first_line, header_line, b'\r\n']
            counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
            rfile = DummyFile(lines.copy())
            self.assertEqual(sys.getrefcount(rfile), 2)
            (first, headers) = backend._read_preamble(rfile)
            self.assertEqual(sys.getrefcount(first), 2)
            self.assertEqual(sys.getrefcount(headers), 2)
            self.assertEqual(rfile._lines, [])
            self.assertEqual(rfile._calls,
                [backend._MAX_LINE_SIZE for i in range(3)]
            )
            self.assertEqual(sys.getrefcount(rfile), 2)
            self.assertEqual(counts,
                tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
            )
            self.assertIsInstance(first, str)
            self.assertEqual(first, first_line[:-2].decode('latin_1'))
            self.assertIsInstance(headers, dict)
            self.assertEqual(headers, {key: value})

        # No headers:
        first_line = random_line()
        lines = [first_line, b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        (first, headers) = backend._read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE, backend._MAX_LINE_SIZE]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )
        self.assertIsInstance(first, str)
        self.assertEqual(first, first_line[:-2].decode('latin_1'))
        self.assertIsInstance(headers, dict)
        self.assertEqual(headers, {})

        # 1 header:
        first_line = random_line()
        header_line = random_header_line()
        lines = [first_line, header_line, b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        (first, headers) = backend._read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        for kv in headers.items():
            self.assertEqual(sys.getrefcount(kv[0]), 3)
            self.assertEqual(sys.getrefcount(kv[1]), 3)
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend._MAX_LINE_SIZE for i in range(3)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )
        self.assertIsInstance(first, str)
        self.assertEqual(first, first_line[:-2].decode('latin_1'))
        self.assertIsInstance(headers, dict)
        self.assertEqual(len(headers), 1)
        key = header_line.split(b': ')[0].decode('latin_1').lower()
        value = headers[key]
        self.assertIsInstance(value, str)
        self.assertEqual(value,
            header_line[:-2].split(b': ')[1].decode('latin_1')
        )

        # _MAX_HEADER_COUNT:
        first_line = random_line()
        header_lines = tuple(
            random_header_line() for i in range(backend._MAX_HEADER_COUNT)
        )
        lines = [first_line]
        lines.extend(header_lines)
        lines.append(b'\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        (first, headers) = backend._read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        for kv in headers.items():
            self.assertEqual(sys.getrefcount(kv[0]), 3)
            self.assertEqual(sys.getrefcount(kv[1]), 3)
        self.assertEqual(rfile._lines, [])
        calls = [
            backend._MAX_LINE_SIZE for i in range(backend._MAX_HEADER_COUNT + 1)
        ]
        calls.append(2)
        self.assertEqual(rfile._calls, calls)
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )
        self.assertIsInstance(first, str)
        self.assertEqual(first, first_line[:-2].decode('latin_1'))
        self.assertIsInstance(headers, dict)
        self.assertEqual(len(headers), len(header_lines))
        for line in header_lines:
            key = line.split(b': ')[0].decode('latin_1').lower()
            value = headers[key]
            self.assertIsInstance(value, str)
            self.assertEqual(value, line[:-2].split(b': ')[1].decode('latin_1'))

    def test__read_preamble_p(self):
        self.check__read_preamble(_basepy)

    def test__read_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check__read_preamble(_base)

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

        # Bad bytes in extension:
        linestart = b'6f0;'
        for bad in helpers.iter_bad_values(8):
            line = linestart + bad + b'\r\n'
            rfile = io.BytesIO(line)
            with self.assertRaises(ValueError) as cm:
                base.read_chunk(rfile)
            if b';' in bad:
                self.assertEqual(str(cm.exception),
                    'bad chunk size line: {!r}'.format(line)
                )
            else:
                self.assertEqual(str(cm.exception),
                    'bad bytes in chunk extension: {!r}'.format(bad)
                )
            self.assertEqual(sys.getrefcount(rfile), 2)
            self.assertEqual(rfile.tell(), 14)

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

