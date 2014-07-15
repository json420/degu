#!/usr/bin/python3

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

import unittest
import io
import sys

import _degu



class DummyFile:
    def __init__(self, lines):
        self._lines = lines

    def readline(self, size=None):
        return self._lines.pop(0)


class TestOS(unittest.TestCase):
    def test_read_preamble(self):
        with self.assertRaises(TypeError) as cm:
            _degu.read_preamble()
        self.assertEqual(str(cm.exception), 
            'read_preamble() takes exactly 1 argument (0 given)'
        )
        with self.assertRaises(TypeError) as cm:
            _degu.read_preamble('foo', 'bar')
        self.assertEqual(str(cm.exception), 
            'read_preamble() takes exactly 1 argument (2 given)'
        )

        lines = [b'D' * 4097]
        rfile = DummyFile(lines.copy())
        with self.assertRaises(ValueError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() returned 4097 bytes, expected at most 4096'
        )
        self.assertEqual(sys.getrefcount(rfile), 2)
        self.assertEqual(rfile._lines, [])
        for i in range(len(lines)):
            self.assertEqual(sys.getrefcount(lines[i]), 2)

        rfile = DummyFile(['hello, world\r\n', b'\r\n'])
        with self.assertRaises(TypeError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception),
            'rfile.readline() must return a bytes instance'
        )

        rfile = io.BytesIO(b'')
        with self.assertRaises(ConnectionError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'HTTP preamble is empty')

        rfile = io.BytesIO(b'\r\n')
        with self.assertRaises(ValueError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'first preamble line is empty')

        rfile = io.BytesIO(b'\n')
        with self.assertRaises(ValueError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'bad line termination')

        rfile = io.BytesIO(b'hello\r\nworld')
        with self.assertRaises(ValueError) as cm:
            _degu.read_preamble(rfile)
        self.assertEqual(str(cm.exception), 'bad line termination')

        rfile = io.BytesIO(b'hello\r\n\r\n')
        self.assertEqual(_degu.read_preamble(rfile), ('hello', []))

        rfile = io.BytesIO(b'hello\r\nFoo: Bar\r\n\r\n')
        self.assertEqual(_degu.read_preamble(rfile), ('hello', ['Foo: Bar']))


if __name__ == '__main__':
    unittest.main()

