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
import ssl
from random import SystemRandom

from .helpers import TempDir, DummySocket
from degu.sslhelpers import random_id
from degu.base import MAX_LINE_BYTES, MAX_HEADER_COUNT
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

    def test_TLS(self):
        self.assertIsInstance(base.TLS, tuple)
        self.assertIsInstance(base.TLS, base._TLS)
        self.assertIs(base.TLS.protocol, ssl.PROTOCOL_TLSv1)
        self.assertIs(base.TLS.name, 'PROTOCOL_TLSv1')
        self.assertEqual(base.TLS.ciphers, 'ECDHE-RSA-AES256-SHA')
        # FIXME: CouchDB isn't playing nice with TLSv1.2, so till we have our
        # own replicator, we need to stick with TLSv1:
        return
        if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            self.assertIs(base.TLS.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertIs(base.TLS.name, 'PROTOCOL_TLSv1_2')
            self.assertEqual(base.TLS.ciphers, 'ECDHE-RSA-AES256-GCM-SHA384')
        else:
            self.assertIs(base.TLS.protocol, ssl.PROTOCOL_TLSv1)
            self.assertIs(base.TLS.name, 'PROTOCOL_TLSv1')
            self.assertEqual(base.TLS.ciphers, 'ECDHE-RSA-AES256-SHA')


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
    def test_build_base_sslctx(self):
        sslctx = base.build_base_sslctx()
        self.assertIsInstance(sslctx, ssl.SSLContext)
        self.assertEqual(sslctx.protocol, base.TLS.protocol)
        self.assertTrue(sslctx.options & ssl.OP_NO_SSLv2)
        self.assertTrue(sslctx.options & ssl.OP_NO_COMPRESSION)
        self.assertIsNone(base.validate_sslctx(sslctx))

    def test_validate_sslctx(self):
        # Bad type:
        with self.assertRaises(TypeError) as cm:
            base.validate_sslctx('foo')
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad protocol:
        with self.assertRaises(ValueError) as cm:
            base.validate_sslctx(ssl.SSLContext(ssl.PROTOCOL_SSLv3))
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.{}'.format(base.TLS.name)
        )

        # Note: Python 3.3.4 (and presumably 3.4.0) now disables SSLv2 by
        # default (which is good); Degu enforces this (also good), but because
        # we cannot unset the ssl.OP_NO_SSLv2 bit, we can't unit test to check
        # that Degu enforces this, so for now, we set the bit here so it works
        # with Python 3.3.3 still; see: http://bugs.python.org/issue20207
        sslctx = ssl.SSLContext(base.TLS.protocol)
        sslctx.options |= ssl.OP_NO_SSLv2

        # Missing ssl.OP_NO_COMPRESSION:
        sslctx.options |= ssl.OP_NO_SSLv2
        with self.assertRaises(ValueError) as cm:
            base.validate_sslctx(sslctx)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # All good:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        self.assertIsNone(base.validate_sslctx(sslctx))

    def test_read_lines_iter(self):
        tmp = TempDir()
        body = b'B' * (MAX_LINE_BYTES + 1)
        toolong = b'L' * (MAX_LINE_BYTES - 1) + b'\r\n'
        self.assertEqual(len(toolong), MAX_LINE_BYTES + 1)

        # Empty:
        rfile = tmp.prepare(b'')
        with self.assertRaises(base.EmptyLineError) as cm:
            list(base.read_lines_iter(rfile))
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)

        # 1st line is too long:
        rfile = tmp.prepare(toolong)
        with self.assertRaises(ValueError) as cm:
            list(base.read_lines_iter(rfile))
        self.assertEqual(str(cm.exception),
            'bad line termination: {!r}'.format(toolong[:MAX_LINE_BYTES])
        )
        self.assertEqual(rfile.tell(), MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)

        # 2nd line is empty (note does not raise EmptyLineError):
        marker = random_id()
        marker_line = marker.encode('latin_1') + b'\r\n'
        rfile = tmp.prepare(marker_line)
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(result, [marker])
        self.assertEqual(str(cm.exception), "bad line termination: b''")
        self.assertEqual(rfile.tell(), len(marker_line))
        self.assertFalse(rfile.closed)

        # 2nd line is too long:
        rfile = tmp.prepare(marker_line + toolong + b'\r\n')
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(result, [marker])
        self.assertEqual(str(cm.exception),
            'bad line termination: {!r}'.format(toolong[:MAX_LINE_BYTES])
        )
        self.assertEqual(rfile.tell(), len(marker_line) + MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)

        ##########################################
        # 11 lines, but missing final termination:
        markers = [random_id() for i in range(11)]
        lines = [M + '\r\n' for M in markers]
        preamble = ''.join(lines).encode('latin_1')
        rfile = tmp.prepare(preamble)
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(str(cm.exception), "bad line termination: b''")
        self.assertEqual(result, markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        # Same, but append with body data:
        rfile = tmp.prepare(preamble + body)
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(str(cm.exception),
            'bad line termination: {!r}'.format(body[:MAX_LINE_BYTES])
        )
        self.assertEqual(result, markers)
        self.assertEqual(rfile.tell(), len(preamble) + MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)

        # Now add final termination:
        lines.append('\r\n')
        preamble = ''.join(lines).encode('latin_1')
        rfile = tmp.prepare(preamble)
        self.assertEqual(list(base.read_lines_iter(rfile)), markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        # Same, but append with body data:
        rfile = tmp.prepare(preamble + body)
        self.assertEqual(list(base.read_lines_iter(rfile)), markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        ##########################################
        # 12 lines, but missing final termination:
        markers = [random_id() for i in range(12)]
        lines = [M + '\r\n' for M in markers]
        preamble = ''.join(lines).encode('latin_1')
        rfile = tmp.prepare(preamble)
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(str(cm.exception), 'too many headers (> 10)')
        self.assertEqual(result, markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        # Same, append a final termination:
        rfile = tmp.prepare(preamble + b'\r\n')
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(str(cm.exception), 'too many headers (> 10)')
        self.assertEqual(result, markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        # Same, but also append body:
        rfile = tmp.prepare(preamble + b'\r\n' + body)
        result = []
        with self.assertRaises(ValueError) as cm:
            for line in base.read_lines_iter(rfile):
                result.append(line)
        self.assertEqual(str(cm.exception), 'too many headers (> 10)')
        self.assertEqual(result, markers)
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertFalse(rfile.closed)

        ###########################
        # Test with a real request:
        preamble = ''.join([
            'POST /dmedia-1 HTTP/1.1\r\n'
            'content-type: application/json\r\n',
            'content-length: 1776\r\n',
            '\r\n',
        ]).encode('latin_1')
        body = os.urandom(17)
        rfile = tmp.prepare(preamble + body)
        self.assertEqual(list(base.read_lines_iter(rfile)), [
            'POST /dmedia-1 HTTP/1.1',
            'content-type: application/json',
            'content-length: 1776',
        ])
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertEqual(rfile.read(), body)
        with self.assertRaises(base.EmptyLineError) as cm:
            list(base.read_lines_iter(rfile))
        self.assertEqual(rfile.tell(), len(preamble) + len(body))
        self.assertFalse(rfile.closed)

        # Same, but when a 2nd request could be read:
        rfile = tmp.prepare(preamble + preamble)
        self.assertEqual(list(base.read_lines_iter(rfile)), [
            'POST /dmedia-1 HTTP/1.1',
            'content-type: application/json',
            'content-length: 1776',
        ])
        self.assertEqual(rfile.tell(), len(preamble))
        self.assertEqual(list(base.read_lines_iter(rfile)), [
            'POST /dmedia-1 HTTP/1.1',
            'content-type: application/json',
            'content-length: 1776',
        ])
        self.assertEqual(rfile.tell(), len(preamble) * 2)
        with self.assertRaises(base.EmptyLineError) as cm:
            list(base.read_lines_iter(rfile))
        self.assertEqual(rfile.tell(), len(preamble) * 2)
        self.assertFalse(rfile.closed)

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
            'bad line termination: {!r}'.format(termed[:MAX_LINE_BYTES])
        )
        self.assertEqual(rfile.tell(), MAX_LINE_BYTES)
        self.assertFalse(rfile.closed)

        # Size line has LF but no CR:
        rfile = tmp.prepare(b'1e61\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b'1e61\\n'")
        self.assertEqual(rfile.tell(), 5)
        self.assertFalse(rfile.closed)

        # Totally empty:
        rfile = tmp.prepare(b'')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad line termination: b''")
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)

        # Size line is property terminated, but empty value:
        rfile = tmp.prepare(b'\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'\\r\\n'"
        )
        self.assertEqual(rfile.tell(), 2)
        self.assertFalse(rfile.closed)

        # Size isn't a hexidecimal integer:
        rfile = tmp.prepare(b'17.6\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6\\r\\n'"
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
        self.assertEqual(str(cm.exception), 'received 6668 bytes, expected 7779')
        self.assertEqual(rfile.tell(), 6674)
        self.assertFalse(rfile.closed)

        # Data isn't properly terminated:
        rfile = tmp.prepare(size + data + b'TT\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad chunk termination: b'TT'")
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
        self.assertEqual(str(cm.exception), 'content-length plus transfer-encoding')

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
