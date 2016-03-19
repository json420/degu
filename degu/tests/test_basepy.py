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
Unit tests for the `degu._basepy` module.
"""

from unittest import TestCase
from random import SystemRandom
import os

from ..sslhelpers import random_id
from .._basepy import TYPE_ERROR, TYPE_ERROR2
from .. import _basepy


random = SystemRandom()


class TestFunctions(TestCase):
    def test_check_type(self):
        _check_type = _basepy._check_type

        # Static value tests:
        self.assertIsNone(_check_type('foo', 17, int))
        with self.assertRaises(TypeError) as cm:
            _check_type('foo', 17.0, int)
        self.assertEqual(str(cm.exception),
            "foo: need a <class 'int'>; got a <class 'float'>: 17.0"
        )

        self.assertIsNone(_check_type('bar', 'hello', str))
        with self.assertRaises(TypeError) as cm:
            _check_type('bar', b'hello', str)
        self.assertEqual(str(cm.exception),
            "bar: need a <class 'str'>; got a <class 'bytes'>: b'hello'"
        )

        self.assertIsNone(_check_type('baz', b'hello', bytes))
        with self.assertRaises(TypeError) as cm:
            _check_type('baz', 'hello', bytes)
        self.assertEqual(str(cm.exception),
            "baz: need a <class 'bytes'>; got a <class 'str'>: 'hello'"
        )

        self.assertIsNone(_check_type('car', [], list))
        with self.assertRaises(TypeError) as cm:
            _check_type('car', {}, list)
        self.assertEqual(str(cm.exception),
            "car: need a <class 'list'>; got a <class 'dict'>: {}"
        )

        self.assertIsNone(_check_type('cdr', {}, dict))
        with self.assertRaises(TypeError) as cm:
            _check_type('cdr', [], dict)
        self.assertEqual(str(cm.exception),
            "cdr: need a <class 'dict'>; got a <class 'list'>: []"
        )

        # Radom value tests:
        values = (
            0,
            random.randrange(-999, 0),
            random.randrange(1, 1001),

            '',
            random_id(15),
            random_id(30),

            b'',
            os.urandom(15),
            os.urandom(30),

            [],
            [random_id()],

            {},
            {random_id(): random_id()},
        )
        for obj in values:
            name = random_id()
            _type = type(obj)
            self.assertIsNone(_check_type(name, obj, _type))

            class subtype(_type):
                pass

            bad = subtype(obj)
            with self.assertRaises(TypeError) as cm:
                _check_type(name, bad, _type)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format(name, _type, subtype, bad)
            )

    def test_check_type2(self):
        _check_type2 = _basepy._check_type2

        # Static value tests:
        self.assertIsNone(_check_type2('foo', 17, int))
        with self.assertRaises(TypeError) as cm:
            _check_type2('foo', 17.0, int)
        self.assertEqual(str(cm.exception),
            "foo: need a <class 'int'>; got a <class 'float'>"
        )

        self.assertIsNone(_check_type2('bar', 'hello', str))
        with self.assertRaises(TypeError) as cm:
            _check_type2('bar', b'hello', str)
        self.assertEqual(str(cm.exception),
            "bar: need a <class 'str'>; got a <class 'bytes'>"
        )

        self.assertIsNone(_check_type2('baz', b'hello', bytes))
        with self.assertRaises(TypeError) as cm:
            _check_type2('baz', 'hello', bytes)
        self.assertEqual(str(cm.exception),
            "baz: need a <class 'bytes'>; got a <class 'str'>"
        )

        self.assertIsNone(_check_type2('car', [], list))
        with self.assertRaises(TypeError) as cm:
            _check_type2('car', {}, list)
        self.assertEqual(str(cm.exception),
            "car: need a <class 'list'>; got a <class 'dict'>"
        )

        self.assertIsNone(_check_type2('cdr', {}, dict))
        with self.assertRaises(TypeError) as cm:
            _check_type2('cdr', [], dict)
        self.assertEqual(str(cm.exception),
            "cdr: need a <class 'dict'>; got a <class 'list'>"
        )

        # Radom value tests:
        values = (
            0,
            random.randrange(-999, 0),
            random.randrange(1, 1001),

            '',
            random_id(15),
            random_id(30),

            b'',
            os.urandom(15),
            os.urandom(30),

            [],
            [random_id()],

            {},
            {random_id(): random_id()},
        )
        for obj in values:
            name = random_id()
            _type = type(obj)
            self.assertIsNone(_check_type2(name, obj, _type))

            class subtype(_type):
                pass

            bad = subtype(obj)
            with self.assertRaises(TypeError) as cm:
                _check_type2(name, bad, _type)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR2.format(name, _type, subtype)
            )

    def test_check_tuple(self):
        _check_tuple = _basepy._check_tuple
        values = tuple(
            tuple(random_id() for i in range(count))
            for count in range(10)
        )
        for obj in values:
            name = random_id()
            size = len(obj)
            self.assertIs(_check_tuple(name, obj, size), obj)
            bad = list(obj)
            with self.assertRaises(TypeError) as cm:
                _check_tuple(name, bad, size)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR2.format(name, tuple, list)
            )
            for offset in (-2, -1, 1, 2):
                s = size + offset
                with self.assertRaises(ValueError) as cm:
                    _check_tuple(name, obj, s)
                self.assertEqual(str(cm.exception),
                    '{}: need a {}-tuple; got a {}-tuple'.format(name, s, size)
                )

    def test_check_list(self):
        _check_list = _basepy._check_list
        values = tuple(
            [random_id() for i in range(count)]
            for count in range(10)
        )
        for obj in values:
            name = random_id()
            self.assertIs(_check_list(name, obj), obj)
            bad = tuple(obj)
            with self.assertRaises(TypeError) as cm:
                _check_list(name, bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR2.format(name, list, tuple)
            )

