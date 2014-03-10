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

This module imports things that often wouldn't normally be needed except for
unit testing, so thus this separate module helps keep the baseline memory
footprint lower.
"""

import tempfile
from os import path
import shutil
import json
from hashlib import sha1
from urllib.parse import urlparse

from .sslhelpers import PKI
from . import start_server, start_sslserver
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


def address_to_url(scheme, address):
    """
    Convert `Server.address` into a URL.

    For example:

    >>> address_to_url('https', ('::1', 54321, 0, 0))
    'https://[::1]:54321/'

    >>> address_to_url('http', ('127.0.0.1', 54321))
    'http://127.0.0.1:54321/'

    """
    assert scheme in ('http', 'https')
    if isinstance(address, (str, bytes)):
        return None
    assert isinstance(address, tuple)
    assert len(address) in {4, 2}
    if len(address) == 2:  # IPv4?
        return '{}://{}:{:d}/'.format(scheme, address[0], address[1])
    # More better, IPv6:
    return '{}://[{}]:{}/'.format(scheme, address[0], address[1])


class TempPKI(PKI):
    def __init__(self, client_pki=False, bits=1024):
        # To make unit testing faster, we use 1024 bit keys by default, but this
        # is not the size you should use in production
        ssldir = tempfile.mkdtemp(prefix='TempPKI.')
        super().__init__(ssldir)
        self.server_ca_id = self.create_key(bits)
        self.create_ca(self.server_ca_id)
        self.server_id = self.create_key(bits)
        self.create_csr(self.server_id)
        self.issue_cert(self.server_id, self.server_ca_id)
        if client_pki:
            self.client_ca_id = self.create_key(bits)
            self.create_ca(self.client_ca_id)
            self.client_id = self.create_key(bits)
            self.create_csr(self.client_id)
            self.issue_cert(self.client_id, self.client_ca_id)
        else:
            self.client_ca_id = None
            self.client_id = None

    def __del__(self):
        if path.isdir(self.ssldir):
            shutil.rmtree(self.ssldir)

    def get_server_config(self):
        return super().get_server_config(self.server_id, self.client_ca_id)

    def get_client_config(self):
        return super().get_client_config(self.server_ca_id, self.client_id)


class _TempProcess:
    def __del__(self):
        self.terminate()

    def terminate(self):
        if getattr(self, 'process', None) is not None:
            self.process.terminate()
            self.process.join()
            self.process = None


class TempServer(_TempProcess):
    def __init__(self, address, build_func, *build_args):
        (self.process, self.address) = start_server(
            address, build_func, *build_args
        )
        self.url = address_to_url('http', self.address)

    def get_client(self):
        return Client(self.address)


class TempSSLServer(_TempProcess):
    def __init__(self, pki, address, build_func, *build_args):
        self.pki = pki
        sslconfig = pki.get_server_config()
        (self.process, self.address) = start_sslserver(
            sslconfig, address, build_func, *build_args
        )
        self.url = address_to_url('https', self.address)

    def get_client(self, sslconfig=None):
        if sslconfig is None:
            sslconfig = self.pki.get_client_config()
        sslctx = build_client_sslctx(sslconfig)
        return SSLClient(sslctx, self.address)

