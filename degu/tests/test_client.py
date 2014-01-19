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
Unit tests for the `degu.server` module`
"""

from unittest import TestCase

from degu import base, client


class TestFunctions(TestCase):
    def test_parse_status(self):
        # Not enough spaces:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200OK')
        self.assertEqual(cm.exception.reason, 'Bad Status Line')

        # Bad protocol:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.0 200 OK')
        self.assertEqual(cm.exception.reason, 'HTTP Version Not Supported')

        # Status not an int:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 17.9 OK')
        self.assertEqual(cm.exception.reason, 'Bad Status Code')

        # Status outside valid range:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 99 OK')
        self.assertEqual(cm.exception.reason, 'Invalid Status Code')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 600 OK')
        self.assertEqual(cm.exception.reason, 'Invalid Status Code')

        # Empty reason:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200 ')
        self.assertEqual(cm.exception.reason, 'Empty Reason')

        # Leading or trailing whitespace in reason:
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  Okey Dokey')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200 Okey Dokey ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')
        with self.assertRaises(base.ParseError) as cm:
            client.parse_status('HTTP/1.1 200  OK ')
        self.assertEqual(cm.exception.reason, 'Extraneous Whitespace In Reason')

        # A gew good static values:
        self.assertEqual(client.parse_status('HTTP/1.1 200 OK'),
            (200, 'OK')
        )
        self.assertEqual(client.parse_status('HTTP/1.1 404 Not Found'),
            (404, 'Not Found')
        )
        self.assertEqual(client.parse_status('HTTP/1.1 505 HTTP Version Not Supported'),
            (505, 'HTTP Version Not Supported')
        )

        # Go through a bunch O permutations:
        for i in range(100, 600):
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo'.format(i)),
                (i, 'Foo')
            )
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo Bar'.format(i)),
                (i, 'Foo Bar')
            )
            self.assertEqual(
                client.parse_status('HTTP/1.1 {:d} Foo Bar Baz'.format(i)),
                (i, 'Foo Bar Baz')
            )

