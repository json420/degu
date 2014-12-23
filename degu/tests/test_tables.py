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

    def test_KEYS(self):
        self.check_allowed(tables.KEYS)
        self.assertEqual(min(tables.KEYS), ord('-'))
        self.assertEqual(max(tables.KEYS), ord('z'))
        self.assertEqual(len(tables.KEYS), 63)

    def test_URI(self):
        self.check_allowed(tables.URI)
        self.assertEqual(min(tables.URI), ord('%'))
        self.assertEqual(max(tables.URI), ord('~'))
        self.assertEqual(len(tables.URI), 73)

    def test_VALUES(self):
        self.check_allowed(tables.VALUES)
        for i in range(128):
            if chr(i).isprintable():
                self.assertIn(i, tables.VALUES)
        self.assertEqual(min(tables.VALUES), ord(' '))
        self.assertEqual(max(tables.VALUES), ord('~'))
        self.assertEqual(len(tables.VALUES), 95)
        self.assertTrue(set(tables.VALUES).issuperset(tables.KEYS))

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

    def test_KEYS_DEF(self):
        self.check_definition(tables.KEYS_DEF, tables.KEYS, True)

    def test_VALUES_DEF(self):
        self.check_definition(tables.VALUES_DEF, tables.VALUES, False)

