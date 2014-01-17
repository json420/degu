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
Unit tests for the `degu.parser` module`
"""

from unittest import TestCase
import os
from random import SystemRandom

from dbase32 import random_id

from .helpers import TempDir
from degu.parser import MAX_LINE_BYTES
from degu import parser


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


class TestFunctions(TestCase):
    def test_read_line(self):
        tmp = TempDir()
        good = (b'G' * (MAX_LINE_BYTES - 2)) + b'\r\n'
        bad1 = (b'B' * (MAX_LINE_BYTES - 1)) + b'\n'
        bad2 = (b'b' * MAX_LINE_BYTES)
        long1 = (b'L' * (MAX_LINE_BYTES + 1))
        long2 = (b'l' * (MAX_LINE_BYTES - 1)) + b'\r\n'
        short = b'hello world\r\n'
        short_bad = b'hello naughty nurse\n'

        for line in (good, bad1, bad2):
            self.assertEqual(len(line), MAX_LINE_BYTES)
        for line in (long1, long2):
            self.assertEqual(len(line), MAX_LINE_BYTES + 1)
        for line in (good, long2, short):
            self.assertEqual(line[-2:], b'\r\n')

        # Line too long, missing CRLF:
        fp = tmp.prepare(long1)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Line too long, valid CRLF:
        fp = tmp.prepare(long2)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Max line lenth, but missing CRLF:
        fp = tmp.prepare(bad1)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Max line lenth, has LF, but missing CR:
        fp = tmp.prepare(b'L' * 4096)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Empty line:
        fp = tmp.prepare(b'')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Bunch O permutations:
        for extra in (b'', good, bad1, bad2, long1, long2, short, short_bad):
            fp = tmp.prepare(good + extra)
            self.assertEqual(parser.read_line(fp),
                ('G' * (MAX_LINE_BYTES - 2))
            )
            fp = tmp.prepare(short + extra)
            self.assertEqual(parser.read_line(fp), 'hello world')
            fp = tmp.prepare(b'\r\n' + extra)
            self.assertEqual(parser.read_line(fp), '')

        # With real request lines:
        lines = b''.join([
            b'POST /dmedia-1 HTTP/1.1\r\n'
            b'content-type: application/json\r\n',
            b'content-length: 1776\r\n',
            b'\r\n',
        ])
        fp = tmp.prepare(lines)
        self.assertEqual(parser.read_line(fp), 'POST /dmedia-1 HTTP/1.1')
        self.assertEqual(parser.read_line(fp), 'content-type: application/json')
        self.assertEqual(parser.read_line(fp), 'content-length: 1776')
        self.assertEqual(parser.read_line(fp), '')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_line(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

    def test_read_chunk(self):
        tmp = TempDir()
        data = (b'D' * 7777)  # Longer than MAX_LINE_BYTES
        small_data = (b'd' * 6666)  # Still longer than MAX_LINE_BYTES
        termed = data + b'\r\n'
        self.assertEqual(len(termed), 7779)
        size = b'1e61\r\n'

        # No CRLF terminated chunk size line:
        fp = tmp.prepare(termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')
        self.assertEqual(fp.tell(), MAX_LINE_BYTES)

        # Size line has LF but no CR:
        fp = tmp.prepare(b'1e61\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')
        self.assertEqual(fp.tell(), 5)

        # Totally empty:
        fp = tmp.prepare(b'')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')
        self.assertEqual(fp.tell(), 0)

        # Size line is property terminated, but empty value:
        fp = tmp.prepare(b'\r\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Chunk Size')
        self.assertEqual(fp.tell(), 2)

        # Size isn't a hexidecimal integer:
        fp = tmp.prepare(b'17.6\r\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Chunk Size')
        self.assertEqual(fp.tell(), 6)
        fp = tmp.prepare(b'17.6; 1e61\r\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Chunk Size')
        self.assertEqual(fp.tell(), 12)

        # Size is negative:
        fp = tmp.prepare(b'-1e61\r\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Negative Chunk Size')
        self.assertEqual(fp.tell(), 7)
        fp = tmp.prepare(b'-1e61; 1e61\r\n' + termed)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Negative Chunk Size')
        self.assertEqual(fp.tell(), 13)

        # Not enough data:
        fp = tmp.prepare(size + small_data + b'\r\n')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Not Enough Chunk Data Provided')
        self.assertEqual(fp.tell(), 6674)

        # Data isn't properly terminated:
        fp = tmp.prepare(size + data + b'TT\r\n')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_chunk(fp)
        self.assertEqual(cm.exception.reason, 'Bad Chunk Termination')
        self.assertEqual(fp.tell(), 7785)

        # Test when it's all good:
        fp = tmp.prepare(size + termed)
        self.assertEqual(parser.read_chunk(fp), data)
        self.assertEqual(fp.tell(), 7785)

    def test_write_chunk(self):
        tmp = TempDir()

        (filename, fp) = tmp.create('zero')
        self.assertIsNone(parser.write_chunk(fp, b''))
        fp.close()
        self.assertEqual(open(filename, 'rb').read(), b'0\r\n\r\n')

        (filename, fp) = tmp.create('one')
        self.assertIsNone(parser.write_chunk(fp, b'hello'))
        fp.close()
        self.assertEqual(open(filename, 'rb').read(), b'5\r\nhello\r\n')

        data = b'D' * 7777
        (filename, fp) = tmp.create('two')
        self.assertIsNone(parser.write_chunk(fp, data))
        fp.close()
        self.assertEqual(open(filename, 'rb').read(),
            b'1e61\r\n' + data + b'\r\n'
        )

        # Test random value round-trip with read_chunk():
        for size in range(1776):
            filename = tmp.join(random_id())
            fp = open(filename, 'xb')
            data = os.urandom(size)
            self.assertIsNone(parser.write_chunk(fp, data))
            fp.close()
            fp = open(filename, 'rb')
            self.assertEqual(parser.read_chunk(fp), data)
            fp.close()

    def test_parse_header(self):
        # Bad separator:
        with self.assertRaises(parser.ParseError) as cm:
            parser.parse_header('Content-Type:application/json')
        self.assertEqual(cm.exception.reason, 'Bad Header Line')

        # Bad Content-Length:
        with self.assertRaises(parser.ParseError) as cm:
            parser.parse_header('Content-Length: 16.9')
        self.assertEqual(cm.exception.reason, 'Bad Content-Length')

        # Negative Content-Length:
        with self.assertRaises(parser.ParseError) as cm:
            parser.parse_header('Content-Length: -17')
        self.assertEqual(cm.exception.reason, 'Negative Content-Length')

        # Bad Transfer-Encoding:
        with self.assertRaises(parser.ParseError) as cm:
            parser.parse_header('Transfer-Encoding: clumped')
        self.assertEqual(cm.exception.reason, 'Bad Transfer-Encoding')

        # Test a number of good values:
        self.assertEqual(parser.parse_header('Content-Type: application/json'),
            ('content-type', 'application/json')
        )
        self.assertEqual(parser.parse_header('Content-Length: 17'),
            ('content-length', 17)
        )
        self.assertEqual(parser.parse_header('Content-Length: 0'),
            ('content-length', 0)
        )
        self.assertEqual(parser.parse_header('Transfer-Encoding: chunked'),
            ('transfer-encoding', 'chunked')
        )

        # Throw a few random values through it:
        for i in range(25):
            key = random_id()
            value = random_id()
            line = '{}: {}'.format(key, value)
            self.assertEqual(parser.parse_header(line),
                (key.casefold(), value)
            )

    def test_read_headers(self):
        tmp = TempDir()

        # 10 headers, but missing the final CRLF:
        headers = random_headers(10)
        lines = build_header_lines(headers)
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Add the final CRLF, should work:
        fp = tmp.prepare(lines + b'\r\n')
        self.assertEqual(parser.read_headers(fp), casefold_headers(headers))

        # 11 headers, ParseError should be raised even without final CRLF:
        headers = random_headers(11)
        lines = build_header_lines(headers)
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Too Many Headers')
        self.assertEqual(fp.tell(), 594)

        # And get a ParseError just the same with the final CRLF:
        fp = tmp.prepare(lines + b'\r\n')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Too Many Headers')
        self.assertEqual(fp.tell(), 594)  # Note did not read to end

        # ParseError should be raised upon a duplicate header name:
        headers = random_headers(9)
        dup = random.choice(tuple(headers)).casefold()
        headers[dup] = random_id()
        self.assertEqual(len(headers), 10)
        lines = build_header_lines(headers)
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Duplicate Header')

        # And the same with the final CRLF:
        fp = tmp.prepare(lines + b'\r\n')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Duplicate Header')

        # Test when there is nothing to read:
        fp = tmp.prepare(b'')
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')

        # Test when there are zero headers:
        fp = tmp.prepare(b'\r\n')
        self.assertEqual(parser.read_headers(fp), {})

        # Test a simple, hard-coded example:
        lines = b'Content-Type: text/plain\r\nContent-Length: 17\r\n\r\n'
        fp = tmp.prepare(lines)
        self.assertEqual(parser.read_headers(fp),
            {'content-type': 'text/plain', 'content-length': 17}
        )
        self.assertEqual(fp.tell(), len(lines))

        # Similar to above, but with a broken line termination:
        lines = b'Content-Type: text/plain\r\nContent-Length: 17\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Line Termination')
        self.assertEqual(fp.tell(), len(lines) - 2)

        # Test with a mallformed header line:
        lines = b'Content-Type: text/plain\r\nContent-Length:17\r\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Header Line')
        self.assertEqual(fp.tell(), len(lines) - 2)

        # Test with a bad content-length:
        lines = b'Content-Type: text/plain\r\nContent-Length: 16.9\r\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Content-Length')
        self.assertEqual(fp.tell(), len(lines) - 2)

        # Test with a negative content-length:
        lines = b'Content-Type: text/plain\r\nContent-Length: -17\r\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Negative Content-Length')
        self.assertEqual(fp.tell(), len(lines) - 2)

        # Test with a bad Transfer-Encoding:
        lines = b'Content-Type: text/plain\r\nTransfer-Encoding: chunky\r\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Bad Transfer-Encoding')
        self.assertEqual(fp.tell(), len(lines) - 2)

        # Test that Content-Length and Transfer-Encoding aren't allowed together:
        lines = b'Transfer-Encoding: chunked\r\nContent-Length: 17\r\n\r\n'
        fp = tmp.prepare(lines)
        with self.assertRaises(parser.ParseError) as cm:
            parser.read_headers(fp)
        self.assertEqual(cm.exception.reason, 'Content-Length With Transfer-Encoding')
        self.assertEqual(fp.tell(), len(lines))

