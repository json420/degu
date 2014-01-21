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
Some tools for unit testing.
"""

import tempfile
from os import path
import shutil

from .sslhelpers import PKI


class TempPKI(PKI):
    def __init__(self, client_pki=False, bits=1024):
        # To make unit testing faster, we use 1024 bit keys by default, but this
        # is not the size you should use in production
        ssldir = tempfile.mkdtemp(prefix='TempPKI.')
        super().__init__(ssldir)
        self.server_ca = self.create_key(bits)
        self.create_ca(self.server_ca)
        self.server = self.create_key(bits)
        self.create_csr(self.server)
        self.issue_cert(self.server, self.server_ca)
        if client_pki:
            self.client_ca = self.create_key(bits)
            self.create_ca(self.client_ca)
            self.client = self.create_key(bits)
            self.create_csr(self.client)
            self.issue_cert(self.client, self.client_ca)
        else:
            self.client_ca = None
            self.client = None
        self.server_config = self.get_server_config(self.server, self.client_ca)
        self.client_config = self.get_client_config(self.server_ca, self.client)

    def __del__(self):
        if path.isdir(self.ssldir):
            shutil.rmtree(self.ssldir)
