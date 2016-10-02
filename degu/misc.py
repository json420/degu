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
Some tools for unit testing.

This module imports things that often wouldn't normally be needed except for
unit testing, so thus this separate module helps keep the baseline memory
footprint lower.
"""

import tempfile
import os
import shutil
import multiprocessing
import logging

from .base import _TYPE_ERROR
from .sslhelpers import PKI as _PKI
from .server import Server, SSLServer, Request
try:
    from ._base import (
        parse_headers,
        write_chunk,
    )
except ImportError:
    from ._basepy import (
        parse_headers,
        write_chunk,
    )


__all__ = ('parse_headers', 'write_chunk')


log = logging.getLogger(__name__)


def mkreq(method, uri, headers=None, body=None, shift=0, cls=Request):
    """
    Shortcut for making a `Request` object for unit testing and demonstration.

    This function is handy for unit test when one needs to build a `Request`
    object.  It will parse the URI out into `mouth`, `path`, and `query`
    components.

    For example:

    >>> r = mkreq('GET', '/foo/bar')
    >>> r.mount
    []
    >>> r.path
    ['foo', 'bar']
    >>> r.query is None
    True

    """
    assert isinstance(shift, int) and shift >= 0
    parts = uri.split('?', 1)
    mount = []
    path = ([] if parts[0] == '/' else parts[0][1:].split('/'))
    for i in range(shift):
        mount.append(path.pop(0)) 
    query = (parts[1] if len(parts) == 2 else None)
    headers = ({} if headers is None else headers)
    return cls(method, uri, headers, body, mount, path, query)


def mkuri(*path, query=None):
    """
    Build an HTTP request URI from RGI *path* and *query* components.

    This function is handy for unit testing when building a URI from the
    components of an RGI `request` object.

    For example:

    >>> mkuri()
    '/'
    >>> mkuri('foo')
    '/foo'
    >>> mkuri('foo', 'bar')
    '/foo/bar'
    >>> mkuri('foo', 'bar', query='key=value')
    '/foo/bar?key=value'

    """
    uri = '/' + '/'.join(path)
    if query is None:
        return uri
    return '?'.join([uri, query])


def _format_header_lines(headers):
    lines = ['{}: {}'.format(*kv) for kv in headers.items()]
    lines.sort()
    return lines


def format_headers(headers):
    lines = _format_header_lines(headers)
    return '\r\n'.join(lines).encode()


def format_request(method, uri, headers):
    lines = ['{} {} HTTP/1.1'.format(method, uri)]
    lines.extend(_format_header_lines(headers))
    return '\r\n'.join(lines).encode()


def format_response(status, reason, headers):
    lines = ['HTTP/1.1 {} {}'.format(status, reason)]
    lines.extend(_format_header_lines(headers))
    return '\r\n'.join(lines).encode()


class TempPKI(_PKI):
    def __init__(self, client_pki=True, bits=1024):
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

    def __del__(self):
        if os.path.isdir(self.ssldir):
            shutil.rmtree(self.ssldir)

    @property
    def server_sslconfig(self):
        return self.get_server_sslconfig(self.server_id, self.client_ca_id)

    @property
    def client_sslconfig(self):
        return self.get_client_sslconfig(self.server_ca_id, self.client_id)

    @property
    def anonymous_server_sslconfig(self):
        return self.get_anonymous_server_sslconfig(self.server_id)

    @property
    def anonymous_client_sslconfig(self):
        return self.get_anonymous_client_sslconfig(self.server_ca_id)


def _run_server(queue, address, app, **options):
    try:
        httpd = Server(address, app, **options)
        queue.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)
        raise e


def _run_sslserver(queue, sslconfig, address, app, **options):
    try:
        httpd = SSLServer(sslconfig, address, app, **options)
        queue.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)
        raise e


def _start_server(address, app, **options):
    import multiprocessing
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_server,
        args=(queue, address, app),
        kwargs=options,
        daemon=True,
    )
    process.start()
    address = queue.get()
    if isinstance(address, Exception):
        process.terminate()
        process.join()
        raise address
    return (process, address)


def _start_sslserver(sslconfig, address, app, **options):
    if not isinstance(sslconfig, dict):
        raise TypeError(
            _TYPE_ERROR.format('sslconfig', dict, type(sslconfig), sslconfig)
        )
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_sslserver,
        args=(queue, sslconfig, address, app),
        kwargs=options,
        daemon=True,
    )
    process.start()
    address = queue.get()
    if isinstance(address, Exception):
        process.terminate()
        process.join()
        raise address
    return (process, address)


class _TempProcess:
    def __del__(self):
        self.terminate()

    def terminate(self):
        if getattr(self, 'process', None) is not None:
            self.process.terminate()
            self.process.join()


class TempServer(_TempProcess):
    def __init__(self, address, app, **options):
        (self.process, self.address) = _start_server(address, app, **options)
        self.app = app
        self.options = options

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.address, self.app
        )


class TempSSLServer(_TempProcess):
    def __init__(self, sslconfig, address, app, **options):
        self.sslconfig = sslconfig
        (self.process, self.address) = _start_sslserver(
            sslconfig, address, app, **options
        )
        self.app = app
        self.options = options

    def __repr__(self):
        return '{}(<sslconfig>, {!r}, {!r})'.format(
            self.__class__.__name__, self.address, self.app
        )


class RequestLogger:
    def __init__(self, app):
        self.app = app

    def __call__(self, session, request, bodies):
        response = self.app(session, request, bodies)
        log.info('[%d] %s %s --> %s %s', session.requests,
            request.method, request.uri, response[0], response[1]
        )
        return response

