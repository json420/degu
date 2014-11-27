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
Unit tests for the `degu._base` module (the C extension).
"""

from unittest import TestCase

try:
    from degu import _base
except ImportError:
    _base = None


class TestFunctions(TestCase):
    def setUp(self):
        if _base is None:
            self.skipTest('degu._base not available')

    def test_parse_method(self):
        for method in ('GET', 'PUT', 'POST', 'HEAD', 'DELETE'):
            result = _base.parse_method(method)
            self.assertEqual(result, method)
            self.assertIs(_base.parse_method(method), result)
            result2 = _base.parse_method(method.encode())
            self.assertEqual(result2, method)
            self.assertIs(result2, result)
            with self.assertRaises(ValueError) as cm:
                _base.parse_method(method.lower())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

