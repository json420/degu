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
    read_preamble,
    parse_headers,
    write_chunk,
    write_body,
    Body,
    ChunkedBody,
    Input,
    ChunkedInput,
    Output,
    ChunkedOutput,
    FileOutput,
)


Response = namedtuple('Response', 'status reason headers body')


class ClosedConnectionError(Exception):
    """
    Raised by `Connection.request()` when connection is already closed.
    """

    def __init__(self, conn):
        self.conn = conn
        super().__init__(
            'cannot use request() when connection is closed: {!r}'.format(conn)
        )


class UnconsumedResponseError(Exception):
    """
    Raised by `Connection.request()` when previous response body not fully read.
    """

    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous response body not consumed: {!r}'.format(body)
        )


def build_client_sslctx(config):
    """
    Build an ``ssl.SSLContext`` appropriately configured for client use.

    For example:

    >>> config = {
    ...     'check_hostname': False,
    ...     'ca_file': '/my/server.ca',
    ...     'cert_file': '/my/client.cert',
    ...     'key_file': '/my/client.key',
    ... }
    >>> sslctx = build_client_sslctx(config)  #doctest: +SKIP

    """
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if not isinstance(config, dict):
        raise TypeError(
            TYPE_ERROR.format('config', dict, type(config), config)
        )

    # In typical Degu P2P usage, hostname checking is meaningless because we
    # wont be trusting centralized certificate authorities, and will typically
    # only connect to servers via their IP address; however, it's still prudent
    # to make *check_hostname* default to True:
    check_hostname = config.get('check_hostname', True)
    if not isinstance(check_hostname, bool):
        raise TypeError(TYPE_ERROR.format(
            "config['check_hostname']", bool, type(check_hostname), check_hostname
        ))

    # Don't allow 'key_file' to be provided without the 'cert_file':
    if 'key_file' in config and 'cert_file' not in config:
        raise ValueError(
            "config['key_file'] provided without config['cert_file']"
        )

    # For safety and clarity, force all paths to be absolute, normalized paths:
    for key in ('ca_file', 'ca_path', 'cert_file', 'key_file'):
        if key in config:
            value = config[key]
            if value != path.abspath(value):
                raise ValueError(
                    'config[{!r}] is not an absulute, normalized path: {!r}'.format(
                        key, value
                    )
                )

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
        if check_hostname is not True:
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
    elif isinstance(body, Body):
        headers['content-length'] = body.content_length
    elif isinstance(body, ChunkedBody):
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


def write_request(wfile, method, uri, headers, body):
    total = wfile.write(
        '{} {} HTTP/1.1\r\n'.format(method, uri).encode('latin_1')
    )
    for key in sorted(headers):
        total += wfile.write(
            '{}: {}\r\n'.format(key, headers[key]).encode('latin_1')
        )
    total += wfile.write(b'\r\n')
    return total


def read_response(rfile, method):
    (status_line, header_lines) = read_preamble(rfile)
    (status, reason) = parse_status(status_line)
    headers = (parse_headers(header_lines) if header_lines else {})
    if 'content-length' in headers and method != 'HEAD':
        body = Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = ChunkedBody(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


class Connection:
    """
    Represents a specific connection to an HTTP (or HTTPS) server.

    A `Connection` is statefull and is *not* thread-safe.
    """

    def __init__(self, sock, base_headers):
        self.sock = sock
        self.base_headers = base_headers
        (self.rfile, self.wfile) = makefiles(sock)
        self.response_body = None  # Previous Input or ChunkedInput

    def __del__(self):
        self.close()

    @property
    def closed(self):
        return self.sock is None

    def close(self):
        self.response_body = None  # Always deference previous response_body
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock = None

    def request(self, method, uri, headers=None, body=None):
        if self.sock is None:
            raise ClosedConnectionError(self)
        try:
            if not (self.response_body is None or self.response_body.closed):
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
            write_request(self.wfile, method, uri, headers, body)
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
    """
    Represents an HTTP server to which Degu can make client connections.

    A `Client` instance is stateless and thread-safe.
    """

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
        for key in self.base_headers:
            assert isinstance(key, str)
            if key.casefold() != key:
                raise ValueError('non-casefolded header name: {!r}'.format(key))
        for key in ('content-length', 'transfer-encoding'):
            if key in self.base_headers:
                raise ValueError('base_headers cannot include {!r}'.format(key))

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.address)

    def create_socket(self):
        if self.family is None:
            return socket.create_connection(self.address)
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.connect(self.address)
        return sock

    def connect(self):
        return Connection(self.create_socket(), self.base_headers)


class SSLClient(Client):
    """
    Represents an HTTPS server to which Degu can make client connections.

    An `SSLClient` instance is stateless and thread-safe.
    """

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

