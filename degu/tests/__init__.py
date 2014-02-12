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
Unit tests for the `degu` package.
"""

from unittest import TestCase

import degu


class TestConstants(TestCase):
    def test_version(self):
        self.assertIsInstance(degu.__version__, str)
        parts = degu.__version__.split('.')
        self.assertEqual(len(parts), 3)
        for part in parts:
            p = int(part)
            self.assertTrue(p >= 0)
            self.assertEqual(str(p), part)

    def test_ADDRESS_CONSTANTS(self):
        self.assertIsInstance(degu.ADDRESS_CONSTANTS, tuple)
        self.assertEqual(degu.ADDRESS_CONSTANTS, (
            degu.IPv6_LOOPBACK,
            degu.IPv6_ANY,
            degu.IPv4_LOOPBACK,
            degu.IPv4_ANY,
        ))
        for address in degu.ADDRESS_CONSTANTS:
            self.assertIsInstance(address, tuple)
            self.assertIn(len(address), {2, 4})
            self.assertIsInstance(address[0], str)
            self.assertIn(address[0], {'::1', '::', '127.0.0.1', '0.0.0.0'})
            if address[0] in {'::1', '::'}:
                self.assertEqual(len(address), 4)
            else:
                self.assertEqual(len(address), 2)
            for value in address[1:]:
                self.assertIsInstance(value, int)
                self.assertEqual(value, 0)


class TestFunctions(TestCase):
    def test_default_build_func(self):
        marker1 = 'whatever'

        def marker2(request):
            return (200, 'OK', {}, None)

        self.assertIs(degu._default_build_func(marker1), marker1)
        self.assertIs(degu._default_build_func(marker2), marker2)

    def test_validate_build_func(self):
        def my_app(request):
            return (200, 'OK', {}, None)

        def my_build_func(arg1, arg2):  
            assert False  # Should not get called

        self.assertIs(
            degu._validate_build_func(None, my_app),
            degu._default_build_func
        )
        self.assertIs(
            degu._validate_build_func(my_build_func),
            my_build_func
        )
        self.assertIs(
            degu._validate_build_func(my_build_func, 'foo'),
            my_build_func
        )
        self.assertIs(
            degu._validate_build_func(my_build_func, 'foo', 'bar'),
            my_build_func
        )

        with self.assertRaises(TypeError) as cm:
            degu._validate_build_func(None)
        self.assertEqual(str(cm.exception),
            'build_func is None, but len(build_args) != 1'
        )
        with self.assertRaises(TypeError) as cm:
            degu._validate_build_func(None, my_app, 'foo')
        self.assertEqual(str(cm.exception),
            'build_func is None, but len(build_args) != 1'
        )

        with self.assertRaises(TypeError) as cm:
            degu._validate_build_func(None, 'foo')
        self.assertEqual(str(cm.exception),
            'build_func is None, but not callable(build_args[0])'
        )

        with self.assertRaises(TypeError) as cm:
            degu._validate_build_func('foo')
        self.assertEqual(str(cm.exception),
            "build_func: not callable: 'foo'"
        )
        with self.assertRaises(TypeError) as cm:
            degu._validate_build_func('foo', my_app)
        self.assertEqual(str(cm.exception),
            "build_func: not callable: 'foo'"
        )

