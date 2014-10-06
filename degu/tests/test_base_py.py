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
Unit tests for the `degu._basepy` module`
"""

from unittest import TestCase
import io
import os

from degu import _basepy


class TestReader(TestCase):
    def test_init(self):
        raw = io.BytesIO(b'GET / HTTP/1.1\r\n\r\n')
        inst = _basepy.Reader(raw)
        self.assertIs(inst.raw, raw)
        self.assertIsInstance(inst._buf, bytearray)
        self.assertEqual(len(inst._buf), _basepy.MAX_PREAMBLE_BYTES)
        for i in range(_basepy.MAX_PREAMBLE_BYTES):
            self.assertEqual(inst._buf[i], 0)
        self.assertIsInstance(inst._view, memoryview)
        self.assertIs(inst._view.obj, inst._buf)
        self.assertIsInstance(inst._tell, int)
        self.assertEqual(inst._tell, 0)
        self.assertIsInstance(inst._size, int)
        self.assertEqual(inst._size, 0)

    def test_tell(self):
        raw = io.BytesIO(b'GET / HTTP/1.1\r\n\r\n')
        inst = _basepy.Reader(raw)
        self.assertEqual(inst.tell(), 0)
        inst._tell = 42
        self.assertEqual(inst.tell(), 42)

    def test_consume_buffer(self):
        inst = _basepy.Reader(None)
        data = os.urandom(42)
        inst._view[0:42] = data
        inst._size = 42

        # Consume zero bytes:
        self.assertEqual(inst._consume_buffer(0), b'')
        self.assertEqual(inst.tell(), 0)
        self.assertEqual(inst._size, 42)

        # Consume first 17 bytes:
        self.assertEqual(inst._consume_buffer(17), data[:17])
        self.assertEqual(inst.tell(), 17)
        self.assertEqual(inst._size, 25)

        # Consume first 25 bytes:
        self.assertEqual(inst._consume_buffer(25), data[17:])
        self.assertEqual(inst.tell(), 42)
        self.assertEqual(inst._size, 0)

