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

This module imports things that often wouldn't normally be needed, so thus this
separate module helps keep the baseline memory footprint lower.
"""

import tempfile
from os import path
import shutil
import json
from hashlib import sha1
from urllib.parse import urlparse

from .sslhelpers import PKI
from .server import start_server, start_sslserver
from .client import Client, SSLClient, build_client_sslctx


def echo_app(request):
    obj = request.copy()
    for name in ('ResponseBody', 'FileResponseBody', 'ChunkedResponseBody'):
        key = 'rgi.' + name
        obj[key] = repr(obj[key])
    if obj['body'] is not None:
        data = obj['body'].read()
        obj['echo.content_sha1'] = sha1(data).hexdigest()
        obj['body'] = repr(obj['body'])
    body = json.dumps(obj, sort_keys=True, indent=4).encode()
    headers = {
        'content-type': 'application/json',
        'content-length': len(body),
    }
    if request['method'] == 'HEAD':
        return (200, 'OK', headers, None)
    return (200, 'OK', headers, body)


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


class TempServer:
    def __init__(self, build_func, *build_args, **kw):
        (self.process, self.env) = start_server(build_func, *build_args, **kw)
        self.t = urlparse(self.env['url'])

    def __del__(self):
        self.process.terminate()
        self.process.join()

    def get_client(self):
        return Client(self.t.hostname, self.t.port)


class TempSSLServer:
    def __init__(self, pki, build_func, *build_args, **kw):
        assert isinstance(pki, TempPKI)
        self.pki = pki
        (self.process, self.env) = start_sslserver(
            pki.server_config, build_func, *build_args, **kw
        )
        t = urlparse(self.env['url'])
        self.hostname = t.hostname
        self.port = t.port
        assert self.port == self.env['port']
        self.url = self.env['url']

    def __del__(self):
        self.process.terminate()
        self.process.join()

    def get_client(self, sslconfig=None):
        if sslconfig is None:
            sslconfig = self.pki.client_config
        sslctx = build_client_sslctx(sslconfig)
        return SSLClient(sslctx, self.hostname, self.port,
            check_hostname=sslconfig.get('check_hostname', False),
        )
