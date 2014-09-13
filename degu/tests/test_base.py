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
from .helpers import DummySocket, random_data, random_chunks, FuzzTestCase
from degu.sslhelpers import random_id
from degu.base import MAX_LINE_BYTES
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


class TestConstants(TestCase):
    def test_MAX_LINE_BYTES(self):
        self.assertIsInstance(base.MAX_LINE_BYTES, int)
        self.assertGreaterEqual(base.MAX_LINE_BYTES, 1024)
        self.assertEqual(base.MAX_LINE_BYTES % 1024, 0)
        self.assertLessEqual(base.MAX_LINE_BYTES, 8192)

    def test_MAX_HEADER_COUNT(self):
        self.assertIsInstance(base.MAX_HEADER_COUNT, int)
        self.assertGreaterEqual(base.MAX_HEADER_COUNT, 5)
        self.assertLessEqual(base.MAX_HEADER_COUNT, 20)

    def test_MAX_CHUNK_BYTES(self):
        self.assertIsInstance(base.MAX_CHUNK_BYTES, int)
        MiB = 1024 * 1024
        self.assertEqual(base.MAX_CHUNK_BYTES % MiB, 0)
        self.assertGreaterEqual(base.MAX_CHUNK_BYTES, MiB)
        self.assertLessEqual(base.MAX_CHUNK_BYTES, MiB * 32)

    def test_STREAM_BUFFER_BYTES(self):
        self.assertIsInstance(base.STREAM_BUFFER_BYTES, int)
        self.assertEqual(base.STREAM_BUFFER_BYTES % 4096, 0)
        self.assertGreaterEqual(base.STREAM_BUFFER_BYTES, 4096)

    def test_FILE_BUFFER_BYTES(self):
        self.assertIsInstance(base.FILE_BUFFER_BYTES, int)
        MiB = 1024 * 1024
        self.assertEqual(base.FILE_BUFFER_BYTES % MiB, 0)
        self.assertGreaterEqual(base.FILE_BUFFER_BYTES, MiB)


class TestEmptyPreambleError(TestCase):
    def test_init(self):
        e = base.EmptyPreambleError('stuff and junk')
        self.assertIsInstance(e, Exception)
        self.assertIsInstance(e, ConnectionError)
        self.assertIs(type(e), base.EmptyPreambleError)
        self.assertEqual(str(e), 'stuff and junk')


class TestUnderFlowError(TestCase):
    def test_init(self):
        e = base.UnderFlowError(16, 17)
        self.assertIsInstance(e, Exception)
        self.assertNotIsInstance(e, base.OverFlowError)
        self.assertEqual(e.received, 16)
        self.assertEqual(e.expected, 17)
        self.assertEqual(str(e), 'received 16 bytes, expected 17')


class TestOverFlowError(TestCase):
    def test_init(self):
        e = base.OverFlowError(20, 18)
        self.assertIsInstance(e, Exception)
        self.assertNotIsInstance(e, base.UnderFlowError)
        self.assertEqual(e.received, 20)
        self.assertEqual(e.expected, 18)
        self.assertEqual(str(e), 'received 20 bytes, expected 18')


class TestBodyClosedError(TestCase):
    def test_init(self):
        body = random_id()
        e = base.BodyClosedError(body)
        self.assertIsInstance(e, Exception)
        self.assertIs(e.body, body)
        self.assertEqual(str(e), 'body already fully read: {!r}'.format(body))


class FuzzTestFunctions(AlternatesTestCase):
    def test_read_preamble_p(self):
        self.fuzz(_basepy.read_preamble)

    def test_read_preamble_c(self):
        self.skip_if_no_c_ext()
        self.fuzz(_base.read_preamble)

    def test_read_chunk(self):
        self.fuzz(base.read_chunk)


class DummyFile:
    def __init__(self, lines):
        self._lines = lines
        self._calls = []

    def readline(self, size=None):
        self._calls.append(size)
        return self._lines.pop(0)


class UserBytes(bytes):
    pass


class TestFunctions(AlternatesTestCase):
    def test_makefiles(self):
        sock = DummySocket()
        self.assertEqual(base.makefiles(sock), (sock._rfile, sock._wfile))
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

    def check_read_preamble(self, backend):
        self.assertIn(backend, (_basepy, _base))

        # Bad bytes in preamble first line:
        for size in range(1, 8):
            for bad in helpers.iter_bad_values(size):
                data = bad + b'\r\nFoo: Bar\r\nstuff: Junk\r\n\r\n'
                rfile = io.BytesIO(data)
                with self.assertRaises(ValueError) as cm:
                    backend.read_preamble(rfile)
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
                    backend.read_preamble(rfile)
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
                    backend.read_preamble(rfile)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header value: {!r}'.format(bad)
                )
                self.assertEqual(sys.getrefcount(rfile), 2)
                self.assertEqual(rfile.tell(), size + 22)

        # Test number of arguments read_preamble() takes:
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble()
        self.assertIn(str(cm.exception), {
            'read_preamble() takes exactly 1 argument (0 given)',
            "read_preamble() missing 1 required positional argument: 'rfile'"
        })
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble('foo', 'bar')
        self.assertIn(str(cm.exception), {
            'read_preamble() takes exactly 1 argument (2 given)',
            'read_preamble() takes 1 positional argument but 2 were given'
        })

        class Bad1:
            pass

        class Bad2:
            readline = 'not callable'

        # rfile has no `readline` attribute:
        rfile = Bad1()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "'Bad1' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline` is not callable:
        rfile = Bad2()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        ##################################################################
        # `rfile.readline()` raises an exception, doesn't return bytes, or
        # returns too many bytes... all on the first line:

        # Exception raised inside call to `rfile.readline()`:
        rfile = DummyFile([])
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line().decode()]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [UserBytes(random_line())]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [b'D' * (backend.MAX_LINE_BYTES - 1) + b'\r\n']
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line(), random_header_line().decode()]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line(), UserBytes(random_header_line())]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [
            random_line(),
            b'D' * (backend.MAX_LINE_BYTES - 1) + b'\r\n',
        ]
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
            random_header_line() for i in range(backend.MAX_HEADER_COUNT - 1)
        )
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT - 1)
        )
        lines.append(random_header_line().decode())
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT - 1)
        )
        lines.append(UserBytes(random_header_line()))
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT - 1)
        )
        lines.append(b'D' * (backend.MAX_LINE_BYTES - 1) + b'\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
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
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(IndexError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'pop from empty list')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # `rfile.readline()` doesn't return bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        lines.append('\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(str, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        lines.append(UserBytes(b'\r\n'))
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(TypeError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned {!r}, should return {!r}'.format(UserBytes, bytes)
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
            + [2]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # `rfile.readline()` returns more than *size* bytes:
        lines = [random_line()]
        lines.extend(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        lines.append(b'D\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 3 bytes, expected at most 2'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'HTTP preamble is empty')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b'o\\n'")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'first preamble line is empty')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls, [backend.MAX_LINE_BYTES])
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad header line termination: b''")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad header line termination: b'\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad header line termination: b'6\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
                        backend.read_preamble(rfile)
                    self.assertEqual(str(cm.exception),
                        'header line too short: {!r}'.format(badline)
                    )
                    self.assertEqual(rfile._lines, [])
                    self.assertEqual(rfile._calls,
                        [backend.MAX_LINE_BYTES for i in range(len(lines))]
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
                backend.read_preamble(rfile)
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
                [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 10: '16.9'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(3)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'negative content-length: -17')
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(3)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception), "bad transfer-encoding: 'clumped'")
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(3)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "duplicate header: b'Content-Type: text/plain\\r\\n'"
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(3)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(4)]
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
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(4)]
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(counts,
            tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        )

        # Too many headers:
        first_line = random_line()
        header_lines = tuple(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        lines = [first_line]
        lines.extend(header_lines)
        lines.append(b'D\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(ValueError) as cm:
            backend.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(backend.MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile._lines, [])
        calls = [
            backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)
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
            (first, headers) = backend.read_preamble(rfile)
            self.assertEqual(sys.getrefcount(first), 2)
            self.assertEqual(sys.getrefcount(headers), 2)
            self.assertEqual(rfile._lines, [])
            self.assertEqual(rfile._calls,
                [backend.MAX_LINE_BYTES for i in range(3)]
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
        (first, headers) = backend.read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES, backend.MAX_LINE_BYTES]
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
        (first, headers) = backend.read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        for kv in headers.items():
            self.assertEqual(sys.getrefcount(kv[0]), 3)
            self.assertEqual(sys.getrefcount(kv[1]), 3)
        self.assertEqual(rfile._lines, [])
        self.assertEqual(rfile._calls,
            [backend.MAX_LINE_BYTES for i in range(3)]
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

        # MAX_HEADER_COUNT:
        first_line = random_line()
        header_lines = tuple(
            random_header_line() for i in range(backend.MAX_HEADER_COUNT)
        )
        lines = [first_line]
        lines.extend(header_lines)
        lines.append(b'\r\n')
        counts = tuple(sys.getrefcount(lines[i]) for i in range(len(lines)))
        rfile = DummyFile(lines.copy())
        self.assertEqual(sys.getrefcount(rfile), 2)
        (first, headers) = backend.read_preamble(rfile)
        self.assertEqual(sys.getrefcount(first), 2)
        self.assertEqual(sys.getrefcount(headers), 2)
        for kv in headers.items():
            self.assertEqual(sys.getrefcount(kv[0]), 3)
            self.assertEqual(sys.getrefcount(kv[1]), 3)
        self.assertEqual(rfile._lines, [])
        calls = [
            backend.MAX_LINE_BYTES for i in range(backend.MAX_HEADER_COUNT + 1)
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

    def test_read_preamble_p(self):
        self.check_read_preamble(_basepy)

    def test_read_preamble_c(self):
        self.skip_if_no_c_ext()
        self.check_read_preamble(_base)

    def test_read_chunk(self):
        data = (b'D' * 7777)  # Longer than MAX_LINE_BYTES
        small_data = (b'd' * 6666)  # Still longer than MAX_LINE_BYTES
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
        self.assertEqual(rfile.tell(), MAX_LINE_BYTES)
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
            'need 0 <= chunk_size <= {}; got -1'.format(base.MAX_CHUNK_BYTES)
        )
        self.assertEqual(rfile.tell(), 4)
        self.assertFalse(rfile.closed)
        rfile = io.BytesIO(b'-1e61;1e61=bar\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got -7777'.format(base.MAX_CHUNK_BYTES)
        )
        self.assertEqual(rfile.tell(), 16)
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_BYTES:
        line = '{:x}\r\n'.format(base.MAX_CHUNK_BYTES + 1)
        rfile = io.BytesIO(line.encode('latin_1') + data)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= 16777216; got 16777217'
        )
        self.assertEqual(rfile.tell(), len(line))
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_BYTES, with extension:
        line = '{:x};foo=bar\r\n'.format(base.MAX_CHUNK_BYTES + 1)
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
        with self.assertRaises(base.UnderFlowError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'received 6668 bytes, expected 7777')
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
        self.assertEqual(base.read_chunk(rfile), (data, None))
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when size line has extra information:
        rfile = io.BytesIO(size_plus + termed)
        self.assertEqual(base.read_chunk(rfile), (data, ('foo', 'bar')))
        self.assertEqual(rfile.tell(), 7793)
        self.assertFalse(rfile.closed)

        # Test max chunk size:
        data = os.urandom(base.MAX_CHUNK_BYTES)
        line = '{:x}\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (data, None))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

        # Again, with extension:
        data = os.urandom(base.MAX_CHUNK_BYTES)
        line = '{:x};foo=bar\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (data, ('foo', 'bar')))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

    def test_write_chunk(self):
        # len(data) > MAX_CHUNK_BYTES:
        data = b'D' * (base.MAX_CHUNK_BYTES + 1)
        wfile = io.BytesIO()
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, data, None)
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # len(data) > MAX_CHUNK_BYTES, with extension:
        wfile = io.BytesIO()
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, data, ('foo', 'bar'))
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # Empty data:
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, b''), 5)
        self.assertEqual(wfile.getvalue(), b'0\r\n\r\n')

        # Empty data plus extension:
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, b'', ('foo', 'bar')), 13)
        self.assertEqual(wfile.getvalue(), b'0;foo=bar\r\n\r\n')

        # Small data:
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, b'hello'), 10)
        self.assertEqual(wfile.getvalue(), b'5\r\nhello\r\n')

        # Small data plus extension:
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, b'hello', ('foo', 'bar')), 18)
        self.assertEqual(wfile.getvalue(), b'5;foo=bar\r\nhello\r\n')

        # Larger data:
        data = b'D' * 7777
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, data), 7785)
        self.assertEqual(wfile.getvalue(), b'1e61\r\n' + data + b'\r\n')

        # Larger data plus extension:
        data = b'D' * 7777
        wfile = io.BytesIO()
        self.assertEqual(base.write_chunk(wfile, data, ('foo', 'bar')), 7793)
        self.assertEqual(wfile.getvalue(), b'1e61;foo=bar\r\n' + data + b'\r\n')

        # Test random value round-trip with read_chunk():
        for size in range(1776):
            # No extension:
            data = os.urandom(size)
            total = size + len('{:x}'.format(size)) + 4
            fp = io.BytesIO()
            self.assertEqual(base.write_chunk(fp, data), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), (data, None))

            # With extension:
            key = random_id()
            value = random_id()
            total = size + len('{:x};{}={}'.format(size, key, value)) + 4
            fp = io.BytesIO()
            self.assertEqual(base.write_chunk(fp, data, (key, value)), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), (data, (key, value)))

        # Make sure we can round-trip MAX_CHUNK_BYTES:
        size = base.MAX_CHUNK_BYTES
        data = os.urandom(size)
        total = size + len('{:x}'.format(size)) + 4
        fp = io.BytesIO()
        self.assertEqual(base.write_chunk(fp, data), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), (data, None))

        # With extension:
        key = random_id()
        value = random_id()
        total = size + len('{:x};{}={}'.format(size, key, value)) + 4
        fp = io.BytesIO()
        self.assertEqual(base.write_chunk(fp, data, (key, value)), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), (data, (key, value)))

    def test_write_body(self):
        # body is bytes:
        body = random_data()
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, body), len(body))
        self.assertEqual(wfile.tell(), len(body))
        wfile.seek(0)
        self.assertEqual(wfile.read(), body)

        # body is bytearray:
        body = bytearray(body)
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, body), len(body))
        self.assertEqual(wfile.tell(), len(body))
        wfile.seek(0)
        self.assertEqual(wfile.read(), body)

        # body is base.Body:
        data = random_data()
        extra = random_data()
        rfile = io.BytesIO(data + extra)
        body = base.Body(rfile, len(data))
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, body), len(data))
        self.assertEqual(rfile.tell(), len(data))
        self.assertEqual(wfile.tell(), len(data))
        wfile.seek(0)
        self.assertEqual(wfile.read(), data)

        # body is base.BodyIter:
        source = tuple(random_data() for i in range(4))
        content_length = sum(len(data) for data in source)
        body = base.BodyIter(source, content_length)
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, body), content_length)
        self.assertEqual(wfile.tell(), content_length)
        self.assertEqual(wfile.getvalue(), b''.join(source))

        # body is base.ChunkedBody:
        chunks = random_chunks()
        rfile = io.BytesIO()
        total = sum(base.write_chunk(rfile, data) for data in chunks)
        rfile.write(extra)
        rfile.seek(0)
        body = base.ChunkedBody(rfile)
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, body), total)
        self.assertEqual(rfile.tell(), total)
        self.assertEqual(wfile.tell(), total)
        wfile.seek(0)
        gotchunks = []
        while True:
            (data, extension) = base.read_chunk(wfile)
            gotchunks.append(data)
            if not data:
                break
        self.assertEqual(gotchunks, chunks)

        # body is base.ChunkedBodyIter:
        source = [
            (random_data(), (random_id(), random_id())) for i in range(5)
        ]
        source.append((b'', (random_id(), random_id())))
        body = base.ChunkedBodyIter(tuple(source))
        wfile = io.BytesIO()
        total = base.write_body(wfile, body)
        self.assertEqual(wfile.tell(), total)
        wfile.seek(0)
        gotchunks = []
        while True:
            (data, extension) = base.read_chunk(wfile)
            gotchunks.append((data, extension))
            if not data:
                break
        self.assertEqual(gotchunks, source)

        # body is None:
        wfile = io.BytesIO()
        self.assertEqual(base.write_body(wfile, None), 0)
        self.assertEqual(wfile.tell(), 0)
        self.assertEqual(wfile.read(), b'')

        # bad body type:
        wfile = io.BytesIO()
        with self.assertRaises(TypeError) as cm:
            base.write_body(wfile, 'hello')
        self.assertEqual(str(cm.exception),
            "invalid body type: <class 'str'>: 'hello'"
        )


class TestBody(TestCase):
    def test_init(self):
        # No rfile.read attribute:
        with self.assertRaises(AttributeError) as cm:
            base.Body('hello', None)
        self.assertEqual(str(cm.exception),
            "'str' object has no attribute 'read'"
        )

        # rfile.read isn't callable:
        class Nope:
            read = 'hello'

        with self.assertRaises(TypeError) as cm:
            base.Body(Nope, None)
        self.assertEqual(str(cm.exception),
            'rfile.read is not callable: {!r}'.format(Nope)
        )
        nope = Nope()
        with self.assertRaises(TypeError) as cm:
            base.Body(nope, None)
        self.assertEqual(str(cm.exception),
            'rfile.read is not callable: {!r}'.format(nope)
        )

        # Create a good rfile:
        data = os.urandom(69)
        rfile = io.BytesIO(data)

        # Good rfile with bad content_length type:
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, 17.0)
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('content_length', int, float, 17.0)
        )
        self.assertEqual(rfile.tell(), 0)
        with self.assertRaises(TypeError) as cm:
            base.Body(rfile, '17')
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('content_length', int, str, '17')
        )
        self.assertEqual(rfile.tell(), 0)

        # Good rfile with bad content_length value:
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
        self.assertEqual(rfile.tell(), 0)

        # All good:
        body = base.Body(rfile, len(data))
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.content_length, 69)
        self.assertEqual(body.remaining, 69)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(rfile.read(), data)
        self.assertEqual(repr(body), 'Body(<rfile>, 69)')

        # Make sure there is no automagical checking of content_length against rfile:
        rfile.seek(1)
        body = base.Body(rfile, 17)
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.content_length, 17)
        self.assertEqual(body.remaining, 17)
        self.assertEqual(rfile.tell(), 1)
        self.assertEqual(rfile.read(), data[1:])
        self.assertEqual(repr(body), 'Body(<rfile>, 17)')

    def test_read(self):
        data = os.urandom(1776)
        rfile = io.BytesIO(data)
        body = base.Body(rfile, len(data))

        # body.closed is True:
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            body.read()
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1776)

        # Bad size type:
        body.closed = False
        with self.assertRaises(TypeError) as cm:
            body.read(18.0)
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('size', int, float, 18.0)
        )
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1776)
        with self.assertRaises(TypeError) as cm:
            body.read('18')
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('size', int, str, '18')
        )
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1776)

        # Bad size value:
        with self.assertRaises(ValueError) as cm:
            body.read(-1)
        self.assertEqual(str(cm.exception), 'size must be >= 0; got -1')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1776)
        with self.assertRaises(ValueError) as cm:
            body.read(-18)
        self.assertEqual(str(cm.exception), 'size must be >= 0; got -18')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1776)

        # Now read it all at once:
        self.assertEqual(body.read(), data)
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 0)
        with self.assertRaises(base.BodyClosedError) as cm:
            body.read()
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Read it again, this time in parts:
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1776)
        self.assertEqual(body.read(17), data[0:17])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1759)

        self.assertEqual(body.read(18), data[17:35])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 35)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 1741)

        self.assertEqual(body.read(1741), data[35:])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 0)

        self.assertEqual(body.read(1776), b'')
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, True)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        self.assertEqual(body.remaining, 0)

        with self.assertRaises(base.BodyClosedError) as cm:
            body.read(17)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Underflow error when trying to read all:
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1800)
        with self.assertRaises(base.UnderFlowError) as cm:
            body.read()
        self.assertEqual(cm.exception.received, 1776)
        self.assertEqual(cm.exception.expected, 1800)
        self.assertEqual(str(cm.exception),
            'received 1776 bytes, expected 1800'
        )
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

        # Underflow error when read in parts:
        data = os.urandom(35)
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 37)
        self.assertEqual(body.read(18), data[:18])
        self.assertIs(body.chunked, False)
        self.assertIs(body.closed, False)
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(body.content_length, 37)
        self.assertEqual(body.remaining, 19)
        with self.assertRaises(base.UnderFlowError) as cm:
            body.read(19)
        self.assertEqual(cm.exception.received, 17)
        self.assertEqual(cm.exception.expected, 19)
        self.assertEqual(str(cm.exception),
            'received 17 bytes, expected 19'
        )
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
        self.assertEqual(body.remaining, 0)
        with self.assertRaises(base.BodyClosedError) as cm:
            body.read(17)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

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
            self.assertEqual(body.remaining, 0)
            with self.assertRaises(base.BodyClosedError) as cm:
                body.read(17)
            self.assertIs(cm.exception.body, body)
            self.assertEqual(str(cm.exception),
                'body already fully read: {!r}'.format(body)
            )
            self.assertEqual(rfile.read(), trailer)

    def test_iter(self):
        data = os.urandom(1776)

        # content_length=0
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 0)
        self.assertEqual(list(body), [b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(rfile.read(), data)

        # content_length=69
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 69)
        self.assertEqual(list(body), [data[:69], b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), 69)
        self.assertEqual(rfile.read(), data[69:])

        # content_length=1776
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1776)
        self.assertEqual(list(body), [data, b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(rfile.read(), b'')

        # content_length=1777
        rfile = io.BytesIO(data)
        body = base.Body(rfile, 1777)
        with self.assertRaises(base.UnderFlowError) as cm:
            list(body)
        self.assertEqual(cm.exception.received, 1776)
        self.assertEqual(cm.exception.expected, 1777)
        self.assertEqual(str(cm.exception),
            'received 1776 bytes, expected 1777'
        )
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)

        # Make sure data is read in FILE_BUFFER_BYTES chunks:
        data1 = os.urandom(base.FILE_BUFFER_BYTES)
        data2 = os.urandom(base.FILE_BUFFER_BYTES)
        length = base.FILE_BUFFER_BYTES * 2
        rfile = io.BytesIO(data1 + data2)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with smaller final chunk:
        length = base.FILE_BUFFER_BYTES * 2 + len(data)
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data, b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with length 1 byte less than available:
        length = base.FILE_BUFFER_BYTES * 2 + len(data) - 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data[:-1], b''])
        self.assertEqual(body.remaining, 0)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), data[-1:])

        # Again, with length 1 byte *more* than available:
        length = base.FILE_BUFFER_BYTES * 2 + len(data) + 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = base.Body(rfile, length)
        with self.assertRaises(base.UnderFlowError) as cm:
            list(body)
        self.assertEqual(cm.exception.received, 1776)
        self.assertEqual(cm.exception.expected, 1777)
        self.assertEqual(str(cm.exception),
            'received 1776 bytes, expected 1777'
        )
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, True)


class TestChunkedBody(TestCase):
    def test_init(self):
        # No rfile.read attribute:
        with self.assertRaises(AttributeError) as cm:
            base.ChunkedBody('hello')
        self.assertEqual(str(cm.exception),
            "'str' object has no attribute 'read'"
        )

        # rfile.read isn't callable:
        class Nope:
            read = 'hello'

        with self.assertRaises(TypeError) as cm:
            base.ChunkedBody(Nope)
        self.assertEqual(str(cm.exception),
            'rfile.read is not callable: {!r}'.format(Nope)
        )
        nope = Nope()
        with self.assertRaises(TypeError) as cm:
            base.ChunkedBody(nope)
        self.assertEqual(str(cm.exception),
            'rfile.read is not callable: {!r}'.format(nope)
        )

        # All good:
        rfile = io.BytesIO()
        body = base.ChunkedBody(rfile)
        self.assertIs(body.chunked, True)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(repr(body), 'ChunkedBody(<rfile>)')

    def test_readchunk(self):
        chunks = random_chunks()
        self.assertEqual(chunks[-1], b'')
        rfile = io.BytesIO()
        total = sum(base.write_chunk(rfile, data) for data in chunks)
        self.assertEqual(rfile.tell(), total)
        extra = os.urandom(3469)
        rfile.write(extra)
        rfile.seek(0)

        # Test when closed:
        body = base.ChunkedBody(rfile)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            body.readchunk()
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(rfile.closed, False)

        # Test when all good:
        body = base.ChunkedBody(rfile)
        for data in chunks:
            self.assertEqual(body.readchunk(), (data, None))
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(base.BodyClosedError) as cm:
            body.readchunk()
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
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
        total = sum(base.write_chunk(rfile, data) for data in chunks)
        self.assertEqual(rfile.tell(), total)
        extra = os.urandom(3469)
        rfile.write(extra)
        rfile.seek(0)

        # Test when closed:
        body = base.ChunkedBody(rfile)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertIs(rfile.closed, False)

        # Test when all good:
        body = base.ChunkedBody(rfile)
        self.assertEqual(list(body), [(data, None) for data in chunks])
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
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


class TestBodyIter(TestCase):
    def test_init(self):
        # Good source with bad content_length type:
        with self.assertRaises(TypeError) as cm:
            base.BodyIter([], 17.0)
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('content_length', int, float, 17.0)
        )
        with self.assertRaises(TypeError) as cm:
            base.BodyIter([], '17')
        self.assertEqual(str(cm.exception),
            base.TYPE_ERROR.format('content_length', int, str, '17')
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
        self.assertIs(body.source, source)
        self.assertEqual(body.content_length, 17)
        self.assertIs(body.closed, False)

    def test_iter(self):
        source = (b'hello', b'naughty', b'nurse')

        # Test when closed:
        body = base.BodyIter(source, 17)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Should close after one iteration:
        body = base.BodyIter(source, 17)
        self.assertEqual(list(body), [b'hello', b'naughty', b'nurse'])
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # OverFlowError should be raised at first item that pushing total above
        # content_length:
        body = base.BodyIter(source, 4)
        result = []
        with self.assertRaises(base.OverFlowError) as cm:
            for data in body:
                result.append(data)
        self.assertEqual(result, [])
        self.assertEqual(cm.exception.received, 5)
        self.assertEqual(cm.exception.expected, 4)
        self.assertEqual(str(cm.exception), 'received 5 bytes, expected 4')
        self.assertIs(body.closed, True)

        body = base.BodyIter(source, 5)
        result = []
        with self.assertRaises(base.OverFlowError) as cm:
            for data in body:
                result.append(data)
        self.assertEqual(result, [b'hello'])
        self.assertEqual(cm.exception.received, 12)
        self.assertEqual(cm.exception.expected, 5)
        self.assertEqual(str(cm.exception), 'received 12 bytes, expected 5')
        self.assertIs(body.closed, True)

        body = base.BodyIter(source, 12)
        result = []
        with self.assertRaises(base.OverFlowError) as cm:
            for data in body:
                result.append(data)
        self.assertEqual(result, [b'hello', b'naughty'])
        self.assertEqual(cm.exception.received, 17)
        self.assertEqual(cm.exception.expected, 12)
        self.assertEqual(str(cm.exception), 'received 17 bytes, expected 12')
        self.assertIs(body.closed, True)

        body = base.BodyIter(source, 16)
        result = []
        with self.assertRaises(base.OverFlowError) as cm:
            for data in body:
                result.append(data)
        self.assertEqual(result, [b'hello', b'naughty'])
        self.assertEqual(cm.exception.received, 17)
        self.assertEqual(cm.exception.expected, 16)
        self.assertEqual(str(cm.exception), 'received 17 bytes, expected 16')
        self.assertIs(body.closed, True)

        # UnderFlowError should only be raised after all items have been
        # yielded:
        body = base.BodyIter(source, 18)
        result = []
        with self.assertRaises(base.UnderFlowError) as cm:
            for data in body:
                result.append(data)
        self.assertEqual(result, [b'hello', b'naughty', b'nurse'])
        self.assertEqual(cm.exception.received, 17)
        self.assertEqual(cm.exception.expected, 18)
        self.assertEqual(str(cm.exception), 'received 17 bytes, expected 18')
        self.assertIs(body.closed, True)

        # Empty data items are fine:
        source = (b'', b'hello', b'', b'naughty', b'', b'nurse', b'')
        body = base.BodyIter(source, 17)
        self.assertEqual(list(body),
            [b'', b'hello', b'', b'naughty', b'', b'nurse', b'']
        )
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Test with random data of varying sizes:
        source = [os.urandom(i) for i in range(50)]
        random.shuffle(source)
        body = base.BodyIter(tuple(source), sum(range(50)))
        self.assertEqual(list(body), source)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )


class TestChunkedBodyIter(TestCase):
    def test_init(self):
        source = []
        body = base.ChunkedBodyIter(source)
        self.assertIs(body.source, source)
        self.assertIs(body.closed, False)

    def test_iter(self):
        source = (
            (b'hello', None),
            (b'naughty', None),
            (b'nurse', None),
            (b'', None),
        )

        # Test when closed:
        body = base.ChunkedBodyIter(source)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Should close after one iteration:
        body = base.ChunkedBodyIter(source)
        self.assertEqual(list(body), list(source))
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

        # Should raise ChunkError on an empty source:
        body = base.ChunkedBodyIter([])
        result = []
        with self.assertRaises(base.ChunkError) as cm:
            for item in body:
                result.append(item)
        self.assertEqual(result, [])
        self.assertEqual(str(cm.exception), 'final chunk data was not empty')

        # Should raise ChunkError if final chunk isn't empty:
        source = (
            (b'hello', None),
            (b'naughty', None),
            (b'nurse', None),
        )
        body = base.ChunkedBodyIter(source)
        result = []
        with self.assertRaises(base.ChunkError) as cm:
            for item in body:
                result.append(item)
        self.assertEqual(result, list(source))
        self.assertEqual(str(cm.exception), 'final chunk data was not empty')

        # Should raise ChunkError if empty chunk is followed by non-empty:
        source = (
            (b'hello', None),
            (b'naughty', None),
            (b'', None),
            (b'nurse', None),
            (b'', None),
        )
        body = base.ChunkedBodyIter(source)
        result = []
        with self.assertRaises(base.ChunkError) as cm:
            for item in body:
                result.append(item)
        self.assertEqual(result,
            [(b'hello', None), (b'naughty', None), (b'', None)]
        )
        self.assertEqual(str(cm.exception), 'non-empty chunk data after empty')

        # Test with random data of varying sizes:
        source = [(os.urandom(i), None) for i in range(1, 51)]
        random.shuffle(source)
        source.append((b'', None))
        body = base.ChunkedBodyIter(tuple(source))
        self.assertEqual(list(body), source)
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'body already fully read: {!r}'.format(body)
        )

