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

