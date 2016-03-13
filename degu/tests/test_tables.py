# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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
    def test_NEVER_ALLOWED(self):
        self.assertIsInstance(tables.NEVER_ALLOWED, bytes)
        self.assertEqual(len(tables.NEVER_ALLOWED), 161)
        self.assertEqual(tables.NEVER_ALLOWED,
            tables.normalize(tables.NEVER_ALLOWED)
        )
        for b in tables.NEVER_ALLOWED:
            if b < 128:
                self.assertFalse(chr(b).isprintable())

    def test_NEVER_ALLOWED_SET(self):
        self.assertIsInstance(tables.NEVER_ALLOWED_SET, frozenset)
        self.assertEqual(tables.NEVER_ALLOWED_SET,
            frozenset(tables.NEVER_ALLOWED)
        )
        self.assertTrue(
            tables.NEVER_ALLOWED_SET.issuperset(range(32))
        )
        self.assertTrue(
            tables.NEVER_ALLOWED_SET.issuperset(range(127, 256))
        )

    def check_allowed(self, allowed):
        self.assertIsInstance(allowed, bytes)
        self.assertEqual(len(allowed), len(set(allowed)))
        self.assertEqual(allowed, bytes(sorted(set(allowed))))
        for i in range(256):
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
            self.assertTrue(name.isidentifier())
            self.check_allowed(allowed)

    def test_BIT_MASKS_DEF(self):
        self.assertIsInstance(tables.BIT_MASKS_DEF, tuple)
        self.assertGreaterEqual(len(tables.BIT_MASKS_DEF), 6)
        avail_flag_names = frozenset(dict((tables.BIT_FLAGS_DEF)))
        for item in tables.BIT_MASKS_DEF:
            self.assertIsInstance(item, tuple)
            self.assertEqual(len(item), 2)
            (name, flag_names) = item
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 1)
            self.assertTrue(name.isupper())
            self.assertTrue(name.isidentifier())
            self.assertIsInstance(flag_names, tuple)
            self.assertGreaterEqual(len(flag_names), 1)
            self.assertTrue(avail_flag_names.issuperset(flag_names))
            for n in flag_names:
                self.assertIsInstance(n, str)

