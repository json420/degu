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
from collections import namedtuple
import io
import os
from os import path
from urllib.parse import urlparse, ParseResult


from .base import (
    TYPE_ERROR,
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


Response = namedtuple('Response', 'status reason headers body')
CLIENT_SOCKET_TIMEOUT = 15


class UnconsumedResponseError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous response body not consumed: {!r}'.format(body)
        )


def build_client_sslctx(config):
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    # In typical P2P Degu usage, hostname checking is meaningless because we
    # wont be trusting centralized certificate authorities; however, it's still
    # prudent to make *check_hostname* default to True:
    check_hostname = config.get('check_hostname', True)
    assert isinstance(check_hostname, bool)

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    sslctx.options |= ssl.OP_NO_COMPRESSION
    if 'ca_file' in config or 'ca_path' in config:
        sslctx.load_verify_locations(
            cafile=config.get('ca_file'),
            capath=config.get('ca_path'),
        )
    else:
        if not check_hostname:
            raise ValueError(
                'check_hostname must be True when using default verify paths'
            )
        sslctx.set_default_verify_paths()
    if 'cert_file' in config:
        sslctx.load_cert_chain(config['cert_file'],
            keyfile=config.get('key_file')
        )
    sslctx.check_hostname = check_hostname
    return sslctx


def validate_client_sslctx(sslctx):
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if not isinstance(sslctx, ssl.SSLContext):
        raise TypeError('sslctx must be an ssl.SSLContext')
    if sslctx.protocol != ssl.PROTOCOL_TLSv1_2:
        raise ValueError('sslctx.protocol must be ssl.PROTOCOL_TLSv1_2')
    if not (sslctx.options & ssl.OP_NO_COMPRESSION):
        raise ValueError('sslctx.options must include ssl.OP_NO_COMPRESSION')
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


class Connection:
    __slots__ = ('sock', 'rfile', 'wfile', 'base_headers', 'response_body', 'closed')

    def __init__(self, sock, base_headers):
        self.sock = sock
        self.base_headers = base_headers
        (self.rfile, self.wfile) = makefiles(sock)
        self.response_body = None  # Previous Input or ChunkedInput
        self.closed = False

    def __del__(self):
        self.close()

    def close(self):
        if not self.closed:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.closed = True
        assert self.closed is True

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
        try:
            preamble = ''.join(iter_request_lines(method, uri, headers))
            self.wfile.write(preamble.encode('latin_1'))
            if isinstance(body, (bytes, bytearray)):
                self.wfile.write(body)
            elif isinstance(body, (Output, FileOutput)):
                for buf in body:
                    self.wfile.write(buf)
            elif isinstance(body, ChunkedOutput):
                for chunk in body:
                    write_chunk(self.wfile, chunk)
            else:
                assert body is None
            self.wfile.flush()
            response = read_response(self.rfile, method)
            self.response_body = response.body
            return response
        except Exception:
            self.close()
            raise


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
            self.server_hostname = address[0]
        elif isinstance(address, (str, bytes)):
            self.family = socket.AF_UNIX
            self.server_hostname = None
            if isinstance(address, str) and path.abspath(address) != address:
                raise ValueError(
                    'address: bad socket filename: {!r}'.format(address)
                )
        else:
            raise TypeError(
                TYPE_ERROR.format('address', (tuple, str, bytes), type(address), address)
            )
        self.address = address
        self.base_headers = ({} if base_headers is None else base_headers)
        assert isinstance(self.base_headers, dict)

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
        return Connection(self.create_socket())


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
        return self.sslctx.wrap_socket(sock,
            server_hostname=self.server_hostname,
        )


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
    if not base_headers:
        base_headers = {}
    base_headers['host'] = t.netloc
    return Client((t.hostname, port), base_headers)


def create_sslclient(sslctx, url, base_headers=None):
    """
    Convenience function to create an `SSLClient` from a URL.
    """
    t = (url if isinstance(url, ParseResult) else urlparse(url))
    if t.scheme != 'https':
        raise ValueError("scheme must be 'https', got {!r}".format(t.scheme))
    port = (443 if t.port is None else t.port)
    if not base_headers:
        base_headers = {}
    base_headers['host'] = t.netloc
    return SSLClient(sslctx, (t.hostname, port), base_headers)

