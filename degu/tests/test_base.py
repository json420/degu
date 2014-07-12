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

from .helpers import DummySocket, random_data, random_chunks, FuzzTestCase
from degu.sslhelpers import random_id
from degu.base import MAX_LINE_BYTES
from degu import base


random = SystemRandom()


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


class TestFunctions(TestCase):
    def test_makefiles(self):
        sock = DummySocket()
        self.assertEqual(base.makefiles(sock), (sock._rfile, sock._wfile))
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

    def test_read_preamble(self):
        # No data at all, likely connection closed by other end:
        rfile = io.BytesIO(b'')
        with self.assertRaises(base.EmptyPreambleError):
            base.read_preamble(rfile)
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        # Just a \n:
        rfile = io.BytesIO(b'\n')
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad line termination: b'\\n'"
        )
        self.assertEqual(rfile.tell(), 1)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        body = random_body()
        rfile = io.BytesIO(b'\n' + body)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad line termination: b'\\n'"
        )
        self.assertEqual(rfile.tell(), 1)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), body)

        # Just a \r\n:
        rfile = io.BytesIO(b'\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'first preamble line is empty')
        self.assertEqual(rfile.tell(), 2)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        # \n is present within MAX_LINE_BYTES, but isn't preceeded by a \r:
        rfile = io.BytesIO(b'DDD\ndddd\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad line termination: b'D\\n'"
        )
        self.assertEqual(rfile.tell(), 4)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'dddd\r\n')

        # Short, no termination:
        line = random_id().encode('latin_1')
        rfile = io.BytesIO(line)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'bad line termination: {!r}'.format(line[-2:])
        )
        self.assertEqual(rfile.tell(), 24)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        # Too long but terminated:
        rfile = io.BytesIO((b'D' * base.MAX_LINE_BYTES) + b'\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad line termination: b'DD'"
        )
        self.assertEqual(rfile.tell(), base.MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'\r\n')

        rfile = io.BytesIO((b'D' * (base.MAX_LINE_BYTES - 1)) + b'\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            "bad line termination: b'D\\r'"
        )
        self.assertEqual(rfile.tell(), base.MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'\n')

        # Too many headers:
        (first_line, header_lines) = random_lines(base.MAX_HEADER_COUNT + 1)
        self.assertEqual(len(header_lines), 16)
        preamble = encode_preamble(first_line, header_lines)
        rfile = io.BytesIO(preamble)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(base.MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile.tell(), 418)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(),
            header_lines[-1][2:].encode('latin_1') + b'\r\n\r\n'
        )

        (first_line, header_lines) = random_lines(base.MAX_HEADER_COUNT + 1)
        self.assertEqual(len(header_lines), 16)
        preamble = encode_preamble(first_line, header_lines)
        body = random_body()
        rfile = io.BytesIO(preamble + body)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(base.MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile.tell(), 418)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(),
            header_lines[-1][2:].encode('latin_1') + b'\r\n\r\n' + body
        )

        # Two good, static test values: first line only:
        rfile = io.BytesIO(b'hello\r\n\r\n')
        self.assertEqual(base.read_preamble(rfile), ('hello', []))
        self.assertEqual(rfile.tell(), 9)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        rfile = io.BytesIO(b'hello\r\n\r\nbody')
        self.assertEqual(base.read_preamble(rfile), ('hello', []))
        self.assertEqual(rfile.tell(), 9)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'body')

        # Two good, static test values: first line plus one header:
        rfile = io.BytesIO(b'hello\r\nworld\r\n\r\n')
        self.assertEqual(base.read_preamble(rfile), ('hello', ['world']))
        self.assertEqual(rfile.tell(), 16)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        rfile = io.BytesIO(b'hello\r\nworld\r\n\r\nbody')
        self.assertEqual(base.read_preamble(rfile), ('hello', ['world']))
        self.assertEqual(rfile.tell(), 16)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'body')

        # Two good, static test values: first line plus *two* headers:
        rfile = io.BytesIO(b'hello\r\nnaughty\r\nnurse\r\n\r\n')
        self.assertEqual(base.read_preamble(rfile),
            ('hello', ['naughty', 'nurse'])
        )
        self.assertEqual(rfile.tell(), 25)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'')

        rfile = io.BytesIO(b'hello\r\nnaughty\r\nnurse\r\n\r\nbody')
        self.assertEqual(base.read_preamble(rfile),
            ('hello', ['naughty', 'nurse'])
        )
        self.assertEqual(rfile.tell(), 25)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(), b'body')

        # Some good random value permutations:
        for header_count in range(base.MAX_HEADER_COUNT + 1):
            (first_line, header_lines) = random_lines(header_count)
            preamble = encode_preamble(first_line, header_lines)
            body = random_body()
            rfile = io.BytesIO(preamble + body)
            self.assertEqual(base.read_preamble(rfile),
                (first_line, header_lines)
            )
            self.assertEqual(rfile.tell(), len(preamble))
            self.assertEqual(rfile.read(), body)

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

    def test_parse_headers(self):
        # Too few values:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['foo:bar'])
        self.assertEqual(str(cm.exception), 'need more than 1 value to unpack')
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['foo bar'])
        self.assertEqual(str(cm.exception), 'need more than 1 value to unpack')

        # Too many values:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['foo: bar: baz'])
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 2)'
        )

        # Bad Content-Length:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['Content-Length: 16.9'])
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 10: '16.9'"
        )

        # Negative Content-Length:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['Content-Length: -17'])
        self.assertEqual(str(cm.exception), 'negative content-length: -17')

        # Bad Transfer-Encoding:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['Transfer-Encoding: clumped'])
        self.assertEqual(str(cm.exception), "bad transfer-encoding: 'clumped'")

        # Duplicate header:
        lines = ['Content-Type: text/plain', 'content-type: text/plain']
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(lines)
        self.assertEqual(str(cm.exception),
            'duplicates in header_lines:\n  ' + '\n  '.join(lines)
        )

        # Content-Length with Transfer-Encoding:
        lines = ('Content-Length: 17', 'Transfer-Encoding: chunked')
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(lines)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )

        # Test a number of good single values:
        self.assertEqual(base.parse_headers(['Content-Type: application/json']),
            {'content-type': 'application/json'}
        )
        self.assertEqual(base.parse_headers(['Content-Length: 17']),
            {'content-length': 17}
        )
        self.assertEqual(base.parse_headers(['Content-Length: 0']),
            {'content-length': 0}
        )
        self.assertEqual(base.parse_headers(['Transfer-Encoding: chunked']),
            {'transfer-encoding': 'chunked'}
        )

        # Test a few good groups of values:
        lines = (
            'Content-Length: 18',
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: Microfiber/14.04',
        )
        self.assertEqual(base.parse_headers(lines), {
            'content-length': 18,
            'content-type': 'application/json',
            'accept': 'application/json',
            'user-agent': 'Microfiber/14.04',
        })
        lines = (
            'transfer-encoding: chunked',
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: Microfiber/14.04',
        )
        self.assertEqual(base.parse_headers(lines), {
            'transfer-encoding': 'chunked',
            'content-type': 'application/json',
            'accept': 'application/json',
            'user-agent': 'Microfiber/14.04',
        })

        # Throw a few random values through it.  Note that parse_headers() isn't
        # limited by MAX_HEADER_COUNT, only read_lines_iter() is.
        headers = dict(
            ('X-' + random_id(), random_id()) for i in range(25)
        )
        lines = tuple(
            '{}: {}'.format(key, value) for (key, value) in headers.items()
        )
        headers = dict(
            (key.casefold(), value) for (key, value) in headers.items()
        )
        self.assertEqual(base.parse_headers(lines), headers)

        # Sanity check when header names are already casefolded:
        lines = tuple(
            '{}: {}'.format(key, value) for (key, value) in headers.items()
        )
        self.assertEqual(base.parse_headers(lines), headers)

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


class FuzzTestFunctions(FuzzTestCase):
    def test_read_preamble(self):
        self.fuzz(base.read_preamble)

    def test_read_chunk(self):
        self.fuzz(base.read_chunk)


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

