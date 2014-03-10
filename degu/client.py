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
HTTP client.
"""

import socket
import ipaddress
import ssl
from collections import namedtuple
import io
import os
from os import path
from urllib.parse import urlparse, ParseResult


from .base import (
    TYPE_ERROR,
    build_base_sslctx,
    validate_base_sslctx,
    makefiles,
    read_lines_iter,
    parse_headers,
    write_chunk,
    Input,
    ChunkedInput,
    Output,
    ChunkedOutput,
    FileOutput,
)


Connection = namedtuple('Connection', 'sock rfile wfile')
Response = namedtuple('Response', 'status reason headers body')
CLIENT_SOCKET_TIMEOUT = 15


class UnconsumedResponseError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous response body not consumed: {!r}'.format(body)
        )


def build_client_sslctx(config):
    sslctx = build_base_sslctx()
    sslctx.verify_mode = ssl.CERT_REQUIRED
    # Configure certificate authorities used to verify server certs
    if 'ca_file' in config or 'ca_path' in config:
        sslctx.load_verify_locations(
            cafile=config.get('ca_file'),
            capath=config.get('ca_path'),
        )
    else:
        sslctx.set_default_verify_paths()
    # Configure client certificate, if provided
    if 'cert_file' in config:
        sslctx.load_cert_chain(config['cert_file'],
            keyfile=config.get('key_file')
        )
    return sslctx


def validate_client_sslctx(sslctx):
    validate_base_sslctx(sslctx)
    if sslctx.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError('sslctx.verify_mode must be ssl.CERT_REQUIRED')
    return sslctx


def validate_request(method, uri, headers, body):
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ValueError('invalid method: {!r}'.format(method))
    if not uri.startswith('/'):
        raise ValueError('bad uri: {!r}'.format(uri))
    for key in headers:
        if key.casefold() != key:
            raise ValueError('non-casefolded header name: {!r}'.format(key))
    if isinstance(body, (bytes, bytearray)): 
        headers['content-length'] = len(body)
    elif isinstance(body, (Output, FileOutput)):
        headers['content-length'] = body.content_length
    elif isinstance(body, ChunkedOutput):
        headers['transfer-encoding'] = 'chunked'
    elif body is not None:
        raise TypeError('bad request body type: {!r}'.format(type(body)))
    if {'content-length', 'transfer-encoding'}.issubset(headers):
        raise ValueError('content-length with transfer-encoding')
    if body is None:
        for key in ('content-length', 'transfer-encoding'):
            if key in headers:
                raise ValueError(
                    'cannot include {!r} when body is None'.format(key)
                )
    elif method not in {'PUT', 'POST'}:
        raise ValueError('cannot include body in a {} request'.format(method))


def iter_request_lines(method, uri, headers):
    yield '{} {} HTTP/1.1\r\n'.format(method, uri)
    if headers:
        for key in sorted(headers):
            yield '{}: {}\r\n'.format(key, headers[key])
    yield '\r\n'


def parse_status(line):
    """
    Parse the status line.

    The return value will be a ``(status, reason)`` tuple, and the status will
    be converted into an integer:

    >>> parse_status('HTTP/1.1 404 Not Found')
    (404, 'Not Found')

    """
    (protocol, status, reason) = line.split(' ', 2)
    if protocol != 'HTTP/1.1':
        raise ValueError('bad HTTP protocol: {!r}'.format(protocol))
    status = int(status)
    if not (100 <= status <= 599):
        raise ValueError('need 100 <= status <= 599; got {}'.format(status))
    if not reason:
        raise ValueError('empty reason')
    return (status, reason)


def read_response(rfile, method):
    lines = tuple(read_lines_iter(rfile))
    (status, reason) = parse_status(lines[0])
    headers = parse_headers(lines[1:])
    if 'content-length' in headers and method != 'HEAD':
        body = Input(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = ChunkedInput(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


class Client:
    def __init__(self, address, base_headers=None):

        if isinstance(address, tuple):  
            if len(address) == 4:
                self.family = socket.AF_INET6
            elif len(address) == 2:
                self.family = None
            else:
                raise ValueError(
                    'address: must have 2 or 4 items; got {!r}'.format(address)
                )
        elif isinstance(address, (str, bytes)):
            self.family = socket.AF_UNIX
            if isinstance(address, str) and path.abspath(address) != address:
                raise ValueError(
                    'address: bad socket filename: {!r}'.format(address)
                )
        else:
            raise TypeError(
                TYPE_ERROR.format('address', (tuple, str, bytes), type(address), address)
            )
        self.address = address
        try: 
            ipaddress.ip_address(address[0])
            self.host = None
        except ValueError:
            # Only send a "host" header for non-numberic hostname:
            self.host = address[0]
        self.base_headers = ({} if base_headers is None else base_headers)
        assert isinstance(self.base_headers, dict)
        if self.host:
            self.base_headers['host'] = self.host
        self.conn = None
        self.response_body = None  # Previous Input or ChunkedInput

    def __del__(self):
        self.close()

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.address)

    def create_socket(self):
        if self.family is None:
            sock = socket.create_connection(self.address)
        else:
            sock = socket.socket(self.family, socket.SOCK_STREAM)
            sock.connect(self.address)
        #sock.settimeout(CLIENT_SOCKET_TIMEOUT)
        return sock

    def connect(self):
        if self.conn is None:
            sock = self.create_socket()
            (rfile, wfile) = makefiles(sock)
            self.conn = Connection(sock, rfile, wfile)
        return self.conn

    def close(self):
        self.response_body = None
        if getattr(self, 'conn', None) is not None:
            conn = self.conn
            self.conn = None
            try:
                conn.sock.shutdown(socket.SHUT_RDWR)
                conn.rfile.close()
                conn.wfile.close()
                conn.sock.close()
            except OSError:
                pass

    def request(self, method, uri, headers=None, body=None):
        if self.response_body and not self.response_body.closed:
            raise UnconsumedResponseError(self.response_body)
        if headers is None:
            headers = {}
        if isinstance(body, io.BufferedReader):
            if 'content-length' in headers:
                content_length = headers['content-length']
            else:
                content_length = os.stat(body.fileno()).st_size
            body = FileOutput(body, content_length)
        validate_request(method, uri, headers, body)
        headers.update(self.base_headers)
        conn = self.connect()
        try:
            preamble = ''.join(iter_request_lines(method, uri, headers))
            conn.wfile.write(preamble.encode('latin_1'))
            if isinstance(body, (bytes, bytearray)):
                conn.wfile.write(body)
            elif isinstance(body, (Output, FileOutput)):
                for buf in body:
                    conn.wfile.write(buf)
            elif isinstance(body, ChunkedOutput):
                for chunk in body:
                    write_chunk(conn.wfile, chunk)
            else:
                assert body is None
            conn.wfile.flush()
            response = read_response(conn.rfile, method)
            self.response_body = response.body
            return response
        except Exception:
            self.close()
            raise


class SSLClient(Client):
    def __init__(self, sslctx, address, default_headers=None):
        self.sslctx = validate_client_sslctx(sslctx)
        super().__init__(address, default_headers)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address
        )

    def create_socket(self):
        sock = super().create_socket()
        return self.sslctx.wrap_socket(sock, server_hostname=self.host)


def create_client(url, base_headers=None):
    """
    Convenience function to create a `Client` from a URL.

    For example:

    >>> create_client('http://www.example.com/')
    Client(('www.example.com', 80))

    """
    t = (url if isinstance(url, ParseResult) else urlparse(url))
    if t.scheme != 'http':
        raise ValueError("scheme must be 'http', got {!r}".format(t.scheme))
    port = (80 if t.port is None else t.port)
    return Client((t.hostname, port), base_headers)


def create_sslclient(sslctx, url, base_headers=None):
    """
    Convenience function to create an `SSLClient` from a URL.
    """
    t = (url if isinstance(url, ParseResult) else urlparse(url))
    if t.scheme != 'https':
        raise ValueError("scheme must be 'https', got {!r}".format(t.scheme))
    port = (443 if t.port is None else t.port)
    return SSLClient(sslctx, (t.hostname, port), base_headers)

