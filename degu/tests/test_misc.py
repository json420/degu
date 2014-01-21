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
Unit tests the `degu.misc` module.
"""

from unittest import TestCase
from os import path

from degu import sslhelpers, misc


class TestTempPKI(TestCase):
    def test_init(self):
        # Test when client_pki=False:
        pki = misc.TempPKI()
        self.assertGreater(path.getsize(pki.path(pki.server_ca, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_ca, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server, 'cert')), 0)
        self.assertIsNone(pki.client_ca)
        self.assertIsNone(pki.client)
        self.assertEqual(pki.server_config,
            pki.get_server_config(pki.server)
        )
        self.assertEqual(pki.client_config,
            pki.get_client_config(pki.server_ca)
        )
        self.assertTrue(path.isdir(pki.ssldir))
        pki.__del__()
        self.assertFalse(path.exists(pki.ssldir))
        pki.__del__()

        # Test when client_pki=True:
        pki = misc.TempPKI(client_pki=True)
        self.assertGreater(path.getsize(pki.path(pki.server_ca, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server_ca, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.server, 'cert')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_ca, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client_ca, 'ca')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client, 'key')), 0)
        self.assertGreater(path.getsize(pki.path(pki.client, 'cert')), 0)
        self.assertEqual(pki.server_config,
            pki.get_server_config(pki.server, pki.client_ca)
        )
        self.assertEqual(pki.client_config,
            pki.get_client_config(pki.server_ca, pki.client)
        )
        self.assertTrue(path.isdir(pki.ssldir))
        pki.__del__()
        self.assertFalse(path.exists(pki.ssldir))
        pki.__del__()
