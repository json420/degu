1# degu: an embedded HTTP server and client library
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

from .helpers import TempDir, DummySocket
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


def random_lines(header_count=10):
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

    def test_STREAM_BUFFER_BYTES(self):
        self.assertIsInstance(base.STREAM_BUFFER_BYTES, int)
        self.assertEqual(base.STREAM_BUFFER_BYTES % 4096, 0)
        self.assertGreaterEqual(base.STREAM_BUFFER_BYTES, 4096)

    def test_FILE_BUFFER_BYTES(self):
        self.assertIsInstance(base.FILE_BUFFER_BYTES, int)
        MiB = 1024 * 1024
        self.assertEqual(base.FILE_BUFFER_BYTES % MiB, 0)
        self.assertGreaterEqual(base.FILE_BUFFER_BYTES, MiB)


class TestEmptyLineError(TestCase):
    def test_init(self):
        e = base.EmptyLineError('stuff and junk')
        self.assertIsInstance(e, Exception)
        self.assertIsInstance(e, ConnectionError)
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


class TestChunkError(TestCase):
    def test_init(self):
        msg = random_id()
        e = base.ChunkError(msg)
        self.assertIsInstance(e, Exception)
        self.assertEqual(str(e), msg) 


class TestBodyClosedError(TestCase):
    def test_init(self):
        body = random_id()
        e = base.BodyClosedError(body)
        self.assertIsInstance(e, Exception)
        self.assertIs(e.body, body)
        self.assertEqual(str(e), 'cannot iterate, {!r} is closed'.format(body))


class TestFunctions(TestCase):
    def test_read_preamble(self):
        # No data at all, likely connection closed by other end:
        rfile = io.BytesIO(b'')
        with self.assertRaises(base.EmptyLineError):
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
        (first_line, header_lines) = random_lines(11)
        self.assertEqual(len(header_lines), 11)
        preamble = encode_preamble(first_line, header_lines)
        rfile = io.BytesIO(preamble)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(base.MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile.tell(), 288)
        self.assertFalse(rfile.closed)
        self.assertEqual(rfile.read(),
            header_lines[-1][2:].encode('latin_1') + b'\r\n\r\n'
        )

        (first_line, header_lines) = random_lines(11)
        self.assertEqual(len(header_lines), 11)
        preamble = encode_preamble(first_line, header_lines)
        body = random_body()
        rfile = io.BytesIO(preamble + body)
        with self.assertRaises(ValueError) as cm:
            base.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'too many headers (> {!r})'.format(base.MAX_HEADER_COUNT)
        )
        self.assertEqual(rfile.tell(), 288)
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
        for header_count in range(11):
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
        tmp = TempDir()
        data = (b'D' * 7777)  # Longer than MAX_LINE_BYTES
        small_data = (b'd' * 6666)  # Still longer than MAX_LINE_BYTES
        termed = data + b'\r\n'
        self.assertEqual(len(termed), 7779)
        size = b'1e61\r\n'
        size_plus = b'1e61; extra stuff here\r\n'

        # No CRLF terminated chunk size line:
        rfile = tmp.prepare(termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'DD'"
        )

        self.assertEqual(rfile.tell(), MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)

        # Size line has LF but no CR:
        rfile = tmp.prepare(b'1e61\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'1\\n'"
        )
        self.assertEqual(rfile.tell(), 5)
        self.assertFalse(rfile.closed)

        # Totally empty:
        rfile = tmp.prepare(b'')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b''"
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)

        # Size line is property terminated, but empty value:
        rfile = tmp.prepare(b'\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b''"
        )
        self.assertEqual(rfile.tell(), 2)
        self.assertFalse(rfile.closed)

        # Size isn't a hexidecimal integer:
        rfile = tmp.prepare(b'17.6\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 6)
        self.assertFalse(rfile.closed)
        rfile = tmp.prepare(b'17.6; 1e61\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 12)
        self.assertFalse(rfile.closed)

        # Size is negative:
        rfile = tmp.prepare(b'-1e61\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'negative chunk size: -7777')
        self.assertEqual(rfile.tell(), 7)
        self.assertFalse(rfile.closed)
        rfile = tmp.prepare(b'-1e61; 1e61\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'negative chunk size: -7777')
        self.assertEqual(rfile.tell(), 13)
        self.assertFalse(rfile.closed)

        # Not enough data:
        rfile = tmp.prepare(size + small_data + b'\r\n')
        with self.assertRaises(base.UnderFlowError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'received 6668 bytes, expected 7777')
        self.assertEqual(rfile.tell(), 6674)
        self.assertFalse(rfile.closed)

        # Data isn't properly terminated:
        rfile = tmp.prepare(size + data + b'TT\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad chunk data termination: b'TT'")
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when it's all good:
        rfile = tmp.prepare(size + termed)
        self.assertEqual(base.read_chunk(rfile), data)
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when size line has extra information:
        rfile = tmp.prepare(size_plus + termed)
        self.assertEqual(base.read_chunk(rfile), data)
        self.assertEqual(rfile.tell(), 7803)
        self.assertFalse(rfile.closed)

    def test_write_chunk(self):
        tmp = TempDir()

        (filename, fp) = tmp.create('zero')
        self.assertEqual(base.write_chunk(fp, b''), 5)
        fp.close()
        self.assertEqual(open(filename, 'rb').read(), b'0\r\n\r\n')

        (filename, fp) = tmp.create('one')
        self.assertEqual(base.write_chunk(fp, b'hello'), 10)
        fp.close()
        self.assertEqual(open(filename, 'rb').read(), b'5\r\nhello\r\n')

        data = b'D' * 7777
        (filename, fp) = tmp.create('two')
        self.assertEqual(base.write_chunk(fp, data), 7785)
        fp.close()
        self.assertEqual(open(filename, 'rb').read(),
            b'1e61\r\n' + data + b'\r\n'
        )

        # Test random value round-trip with read_chunk():
        for size in range(1776):
            filename = tmp.join(random_id())
            fp = open(filename, 'xb')
            data = os.urandom(size)
            total = size + len('{:x}'.format(size)) + 4
            self.assertEqual(base.write_chunk(fp, data), total)
            fp.close()
            fp = open(filename, 'rb')
            self.assertEqual(base.read_chunk(fp), data)
            fp.close()

    def test_parse_headers(self):
        # Bad separator:
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(['Content-Type:application/json'])
        self.assertEqual(str(cm.exception), 'need more than 1 value to unpack')

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
        lines = ('Content-Type: text/plain', 'content-type: text/plain')
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(lines)
        self.assertEqual(str(cm.exception), "duplicate header: 'content-type'")

        # Content-Length with Transfer-Encoding:
        lines = ('Content-Length: 17', 'Transfer-Encoding: chunked')
        with self.assertRaises(ValueError) as cm:
            base.parse_headers(lines)
        self.assertEqual(str(cm.exception),
            "cannot have both 'content-length' and 'transfer-encoding' headers"
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

    def test_makefiles(self):
        sock = DummySocket()
        self.assertEqual(base.makefiles(sock), (sock._rfile, sock._wfile))
        self.assertEqual(sock._calls, [
            ('makefile', 'rb', {'buffering': base.STREAM_BUFFER_BYTES}),
            ('makefile', 'wb', {'buffering': base.STREAM_BUFFER_BYTES}),
        ])

    def test_make_output_from_input(self):
        tmp = TempDir()

        data = os.urandom(17)
        rfile = tmp.prepare(data)
        input_body = base.Input(rfile, 17)
        output_body = base.make_output_from_input(input_body)
        self.assertIsInstance(output_body, base.Output)
        self.assertIs(output_body.source, input_body)
        self.assertEqual(output_body.content_length, 17)
        self.assertIs(input_body.closed, False)
        self.assertIs(output_body.closed, False)
        self.assertEqual(list(output_body), [data])
        self.assertIs(input_body.closed, True)
        self.assertIs(output_body.closed, True)
        self.assertIs(rfile.closed, False)

        (filename, fp) = tmp.create('foo')
        chunk1 = os.urandom(18)
        chunk2 = os.urandom(21)
        chunk3 = os.urandom(17)
        for chunk in [chunk1, chunk2, chunk3, b'']:
            base.write_chunk(fp, chunk)
        fp.close()
        rfile = open(filename, 'rb')
        input_body = base.ChunkedInput(rfile)
        output_body = base.make_output_from_input(input_body)
        self.assertIsInstance(output_body, base.ChunkedOutput)
        self.assertIs(output_body.source, input_body)
        self.assertIs(input_body.closed, False)
        self.assertIs(output_body.closed, False)
        self.assertEqual(list(output_body), [chunk1, chunk2, chunk3, b''])
        self.assertIs(input_body.closed, True)
        self.assertIs(output_body.closed, True)
        self.assertIs(rfile.closed, False)

        self.assertIsNone(base.make_output_from_input(None))

        with self.assertRaises(TypeError) as cm:
            base.make_output_from_input(b'hello')
        self.assertEqual(str(cm.exception), "bad input_body: <class 'bytes'>")

    def test_build_uri(self):
        self.assertEqual(base.build_uri([], ''), '/')
        self.assertEqual(base.build_uri([], 'q'), '/?q')
        self.assertEqual(base.build_uri(['foo'], ''), '/foo')
        self.assertEqual(base.build_uri(['foo'], 'q'), '/foo?q')
        self.assertEqual(base.build_uri(['foo', ''], ''), '/foo/')
        self.assertEqual(base.build_uri(['foo', ''], 'q'), '/foo/?q')
        self.assertEqual(base.build_uri(['foo', 'bar'], ''), '/foo/bar')
        self.assertEqual(base.build_uri(['foo', 'bar'], 'q'), '/foo/bar?q')
        self.assertEqual(base.build_uri(['foo', 'bar', ''], ''), '/foo/bar/')
        self.assertEqual(base.build_uri(['foo', 'bar', ''], 'q'), '/foo/bar/?q')


class TestOutput(TestCase):
    def test_init(self):
        source = (b'foo', b'bar', b'baz')
        body = base.Output(source, 9)
        self.assertIs(body.closed, False)
        self.assertIs(body.source, source)
        self.assertEqual(body.content_length, 9)

        # Should raise a TypeError if content_length isn't an int:
        with self.assertRaises(TypeError) as cm:
            base.Output(source, '9')
        self.assertEqual(str(cm.exception), 'content_length must be an int')

        # Should raise a ValueError if content_length < 0:
        with self.assertRaises(ValueError) as cm:
            base.Output(source, -1)
        self.assertEqual(str(cm.exception), 'content_length must be >= 0')

    def test_iter(self):
        source = (b'foo', b'bar', b'baz')
        body = base.Output(source, 9)
        self.assertEqual(list(body), [b'foo', b'bar', b'baz'])
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # More bytes yielded from source than expected:
        body = base.Output(source, 8)
        results = []
        with self.assertRaises(base.OverFlowError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception), 'received 9 bytes, expected 8')
        self.assertEqual(results, [b'foo', b'bar'])

        # Fewer bytes yielded from source than expected:
        body = base.Output(source, 10)
        results = []
        with self.assertRaises(base.UnderFlowError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception), 'received 9 bytes, expected 10')
        self.assertEqual(results, [b'foo', b'bar', b'baz'])

        # BodyClosedError should be raised by setting the closed attribute:
        source = (b'foo', b'bar', b'baz')
        body = base.Output(source, 9)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # Should work fine with an empty source:
        body = base.Output([], 0)
        self.assertEqual(list(body), [])
        self.assertIs(body.closed, True)

        # And with a single empty buffer in source:
        body = base.Output([b''], 0)
        self.assertEqual(list(body), [b''])
        self.assertIs(body.closed, True)

        # Should also work with intermixed empty buffers:
        body = base.Output((b'foo', b'', b'bar', b'baz', b''), 9)
        self.assertEqual(list(body), [b'foo', b'', b'bar', b'baz', b''])
        self.assertIs(body.closed, True)

        # Both bytes and bytearray are valid buffer types:
        body = base.Output((b'stuff', bytearray(b'junk')), 9)
        self.assertEqual(list(body), [b'stuff', bytearray(b'junk')])
        self.assertIs(body.closed, True)

        # But str is not a valid buffer type:
        body = base.Output((b'foo', 'bar', b'baz'), 9)
        results = []
        with self.assertRaises(TypeError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception), 'buf must be bytes or bytearray')
        self.assertEqual(results, [b'foo'])
        self.assertIs(body.closed, True)


class TestChunkedOutput(TestCase):
    def test_init(self):
        source = (b'foo', b'bar', b'')
        body = base.ChunkedOutput(source)
        self.assertIs(body.closed, False)
        self.assertIs(body.source, source)

    def test_iter(self):
        source = (b'foo', b'bar', b'')
        body = base.ChunkedOutput(source)
        self.assertEqual(list(body), [b'foo', b'bar', b''])
        self.assertIs(body.closed, True)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # BodyClosedError should be raised by setting the closed attribute:
        body = base.ChunkedOutput(source)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # Non-empty chunk after empty chunk:
        body = base.ChunkedOutput((b'foo', b'bar', b'', b'baz'))
        results = []
        with self.assertRaises(base.ChunkError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception),
            'received non-empty chunk after empty chunk'
        )
        self.assertEqual(results, [b'foo', b'bar', b''])

        # Final chunk not empty:
        body = base.ChunkedOutput((b'foo', b'bar', b'baz'))
        results = []
        with self.assertRaises(base.ChunkError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception),
            'final chunk was not empty'
        )
        self.assertEqual(results, [b'foo', b'bar', b'baz'])

        # Should work fine with a single empty chunk:
        body = base.ChunkedOutput((b'',))
        self.assertEqual(list(body), [b''])
        self.assertIs(body.closed, True)

        # Both bytes and bytearray are valid chunk types:
        body = base.ChunkedOutput((b'stuff', bytearray(b'junk'), b''))
        self.assertEqual(list(body), [b'stuff', bytearray(b'junk'), b''])
        self.assertIs(body.closed, True)

        # But str is not a valid chunk type:
        body = base.ChunkedOutput((b'foo', 'bar', b'baz', b''))
        results = []
        with self.assertRaises(TypeError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception), 'chunk must be bytes or bytearray')
        self.assertEqual(results, [b'foo'])
        self.assertIs(body.closed, True)


class TestFileOutput(TestCase):
    def test_init(self):
        tmp = TempDir()
        data = os.urandom(17)
        fp = tmp.prepare(data)

        body = base.FileOutput(fp, 17)
        self.assertIs(body.closed, False)
        self.assertIs(body.fp, fp)
        self.assertEqual(body.content_length, 17)

        # Should raise a TypeError if fp isn't an io.BufferedReader:
        wfile = open(tmp.join('foo'), 'wb')
        with self.assertRaises(TypeError) as cm:
            base.FileOutput(wfile, 17)
        self.assertEqual(str(cm.exception), 'fp must be an io.BufferedReader')

        # Should raise a TypeError if content_length isn't an int:
        with self.assertRaises(TypeError) as cm:
            base.FileOutput(fp, '17')
        self.assertEqual(str(cm.exception), 'content_length must be an int')

        # Should raise a ValueError if content_length < 0:
        with self.assertRaises(ValueError) as cm:
            base.FileOutput(fp, -1)
        self.assertEqual(str(cm.exception), 'content_length must be >= 0')

        # Should raise a TypeError fp closed:
        fp.close()
        with self.assertRaises(ValueError) as cm:
            base.FileOutput(fp, 17)
        self.assertEqual(str(cm.exception), 'fp is already closed')

    def test_iter(self):
        tmp = TempDir()

        # Test with an empty file:
        fp = tmp.prepare(b'')
        body = base.FileOutput(fp, 0)
        self.assertEqual(list(body), [])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)

        # Full file:
        data = os.urandom(base.FILE_BUFFER_BYTES + 1)
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, base.FILE_BUFFER_BYTES + 1)
        self.assertEqual(list(body), [data[:-1], data[-1:]])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)

        # Check that BodyClosedError is raised in above non-contrived scenario:
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # But should also be raised by merely setting body.closed to True:
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, base.FILE_BUFFER_BYTES + 1)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )

        # From seek(200) to the end of file:
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, base.FILE_BUFFER_BYTES - 199)
        fp.seek(200)
        self.assertEqual(list(body), [data[200:]])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)

        # From start of file up to size - 200:
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, base.FILE_BUFFER_BYTES - 199)
        self.assertEqual(list(body), [data[:-200]])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)

        # A non-inclusive slice:
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, 111)
        fp.seek(666)
        self.assertEqual(list(body), [data[666:777]])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)

        # Not enough content:
        fp = tmp.prepare(data)
        body = base.FileOutput(fp, base.FILE_BUFFER_BYTES + 2)
        results = []
        with self.assertRaises(base.UnderFlowError) as cm:
            for buf in body:
                results.append(buf)
        self.assertEqual(str(cm.exception), 'received 1 bytes, expected 2')
        self.assertEqual(results, [data[:-1]])
        self.assertIs(body.closed, True)
        self.assertIs(body.fp.closed, True)


class TestInput(TestCase):
    def test_init(self):
        tmp = TempDir()
        data = os.urandom(18)
        rfile = tmp.prepare(data)

        body = base.Input(rfile, 18)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.content_length, 18)
        self.assertEqual(body.remaining, 18)
        self.assertEqual(repr(body), 'Input({!r}, 18)'.format(rfile))

        # Should raise a TypeError if rfile isn't an io.BufferedReader:
        wfile = open(tmp.join('foo'), 'wb')
        with self.assertRaises(TypeError) as cm:
            base.Input(wfile, 18)
        self.assertEqual(str(cm.exception), 'rfile must be an io.BufferedReader')

        # Should raise a TypeError if content_length isn't an int:
        with self.assertRaises(TypeError) as cm:
            base.Input(rfile, '18')
        self.assertEqual(str(cm.exception), 'content_length must be an int')

        # Should raise a ValueError if content_length < 0:
        with self.assertRaises(ValueError) as cm:
            base.Input(rfile, -1)
        self.assertEqual(str(cm.exception), 'content_length must be >= 0')

        # Should raise a TypeError if rfile closed:
        rfile.close()
        with self.assertRaises(ValueError) as cm:
            base.Input(rfile, 18)
        self.assertEqual(str(cm.exception), 'rfile is already closed')

    def test_read(self):
        tmp = TempDir()

        total = 1776
        start = random.randrange(total)
        stop = random.randrange(start + 1, total + 1)
        content_length = stop - start
        self.assertTrue(0 <= content_length <= total)
        data = os.urandom(total)
        rfile = tmp.prepare(data)
        rfile.seek(start)
        body = base.Input(rfile, content_length)
        self.assertIs(body.rfile, rfile)
        self.assertEqual(body.content_length, content_length)
        self.assertEqual(body.remaining, content_length)
        self.assertIs(body.closed, False)
        self.assertIs(rfile.closed, False)

        result = body.read()
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), content_length)
        self.assertEqual(result, data[start:stop])
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), stop)

        result = body.read()
        self.assertIsInstance(result, bytes)
        self.assertEqual(result, b'')
        self.assertIs(body.closed, True)
        self.assertIs(rfile.closed, False)
        self.assertEqual(rfile.tell(), stop)

        # Should raise a TypeError if size isn't an int:
        rfile = tmp.prepare(data)
        rfile.seek(start)
        body = base.Input(rfile, content_length)
        with self.assertRaises(TypeError) as cm:
            body.read(str(content_length))
        self.assertEqual(str(cm.exception), 'size must be an int')

        # Should raise a ValueError if size < 0:
        with self.assertRaises(ValueError) as cm:
            body.read(-1)
        self.assertEqual(str(cm.exception), 'size must be >= 0')
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile.closed, False)
        self.assertEqual(body.rfile.tell(), start)

    def test_iter(self):
        buf1 = os.urandom(base.FILE_BUFFER_BYTES)
        buf2 = os.urandom(base.FILE_BUFFER_BYTES)
        buf3 = os.urandom(21)
        data = buf1 + buf2 + buf3
        tmp = TempDir()

        # Reading all:
        rfile = tmp.prepare(data)
        body = base.Input(rfile, len(data))
        self.assertEqual(list(body), [buf1, buf2, buf3])
        self.assertIs(body.closed, True)
        self.assertIs(body.rfile.closed, False)
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )


class TestChunkedInput(TestCase):
    def test_init(self):
        tmp = TempDir()
        data = os.urandom(18)
        rfile = tmp.prepare(data)

        body = base.ChunkedInput(rfile)
        self.assertIs(body.closed, False)
        self.assertIs(body.rfile, rfile)

        # Should raise a TypeError if rfile isn't an io.BufferedReader:
        wfile = open(tmp.join('foo'), 'wb')
        with self.assertRaises(TypeError) as cm:
            base.ChunkedInput(wfile)
        self.assertEqual(str(cm.exception), 'rfile must be an io.BufferedReader')

        # Should raise a TypeError if rfile closed:
        rfile.close()
        with self.assertRaises(ValueError) as cm:
            base.ChunkedInput(rfile)
        self.assertEqual(str(cm.exception), 'rfile is already closed')

    def test_read(self):
        chunk1 = os.urandom(random.randrange(1, 1777))
        chunk2 = os.urandom(random.randrange(1, 1777))
        chunk3 = os.urandom(random.randrange(1, 1777))
        for chunk in [chunk1, chunk2, chunk3]:
            self.assertTrue(
                1 <= len(chunk) <= (3 * 1776)
            )
        tmp = TempDir()

        # Test when 1st chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(body.read(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)
        self.assertEqual(body.read(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)
        fp.close()

        # Now test when 4th chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [chunk1, chunk2, chunk3, b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(body.read(), chunk1 + chunk2 + chunk3)
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        final = fp.tell()
        self.assertEqual(body.read(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), final)

    def test_readchunk(self):
        chunk1 = os.urandom(random.randrange(1, 1777))
        chunk2 = os.urandom(random.randrange(1, 1777))
        chunk3 = os.urandom(random.randrange(1, 1777))
        for chunk in [chunk1, chunk2, chunk3]:
            self.assertTrue(
                1 <= len(chunk) <= (3 * 1776)
            )
        tmp = TempDir()

        # Test when 1st chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)
        fp.close()

        # Now test when 4th chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [chunk1, chunk2, chunk3, b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(body.readchunk(), chunk1)
        self.assertEqual(body.readchunk(), chunk2)
        self.assertEqual(body.readchunk(), chunk3)
        self.assertIs(body.closed, False)
        self.assertIs(fp.closed, False)
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        final = fp.tell()
        self.assertEqual(body.readchunk(), b'')
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), final)

    def test_iter(self):
        chunk1 = os.urandom(random.randrange(1, 1777))
        chunk2 = os.urandom(random.randrange(1, 1777))
        chunk3 = os.urandom(random.randrange(1, 1777))
        for chunk in [chunk1, chunk2, chunk3]:
            self.assertTrue(
                1 <= len(chunk) <= (3 * 1776)
            )
        tmp = TempDir()

        # Test when 1st chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(list(body), [b''])
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)

        # Should now raise BodyClosedError:
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 5)

        # Should also raise BodyClosedError merely by setting closed to True:
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        body.closed = True
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), 0)

        # Now test when 4th chunk is empty:
        (filename, fp) = tmp.create(random_id())
        for chunk in [chunk1, chunk2, chunk3, b'', chunk2]:
            base.write_chunk(fp, chunk)
        fp.close()
        fp = open(filename, 'rb')
        body = base.ChunkedInput(fp)
        self.assertEqual(list(body), [chunk1, chunk2, chunk3, b''])
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        final = fp.tell()
        with self.assertRaises(base.BodyClosedError) as cm:
            list(body)
        self.assertIs(cm.exception.body, body)
        self.assertEqual(str(cm.exception),
            'cannot iterate, {!r} is closed'.format(body)
        )
        self.assertIs(body.closed, True)
        self.assertIs(fp.closed, False)
        self.assertEqual(fp.tell(), final)
