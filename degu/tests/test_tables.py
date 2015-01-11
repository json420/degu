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
Unit tests the `degu.tables` module.
"""

from unittest import TestCase

from degu import tables


class TestConstants(TestCase):
    def check_allowed(self, allowed):
        self.assertIsInstance(allowed, bytes)
        self.assertEqual(len(allowed), len(set(allowed)))
        self.assertEqual(allowed, bytes(sorted(set(allowed))))
        for i in range(128):
            if not chr(i).isprintable():
                self.assertNotIn(i, allowed)
        for i in allowed:
            self.assertEqual(i & 128, 0)

    def test_NAMES_DEF(self):
        self.check_allowed(tables.NAMES_DEF)
        self.assertEqual(min(tables.NAMES_DEF), ord('-'))
        self.assertEqual(max(tables.NAMES_DEF), ord('z'))
        self.assertEqual(len(tables.NAMES_DEF), 63)

    def test_BIT_FLAGS_DEF(self):
        self.assertIsInstance(tables.BIT_FLAGS_DEF, tuple)
        self.assertEqual(len(tables.BIT_FLAGS_DEF), 7)
        for item in tables.BIT_FLAGS_DEF:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)
            (name, allowed) = item
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 1)
            self.assertTrue(name.isupper())
            self.check_allowed(allowed)

    def check_definition(self, definition, allowed, casefold):
        self.assertIsInstance(definition, tuple)
        self.assertEqual(len(definition), 256)
        for (index, item) in enumerate(definition):
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)
            (i, r) = item
            self.assertIsInstance(i, int)
            self.assertEqual(i, index)
            self.assertIsInstance(r, int)
            if i in allowed:
                self.assertEqual(i & 128, 0)
                if casefold:
                    self.assertEqual(r, ord(chr(i).lower()))
                else:
                    self.assertEqual(r, i)
            else:
                self.assertEqual(r, 255)
            if not (32 <= i <= 126):
                self.assertEqual(r, 255)
        self.assertEqual(definition, tuple(sorted(definition)))


