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
import ssl
from collections import namedtuple

from .base import (
    ParseError,
    makefiles,
    read_line,
    read_headers,
    write_chunk,
    Input,
    ChunkedInput,
    Output,
    ChunkedOutput,
    FileOutput,
)


Connection = namedtuple('Connection', 'sock rfile wfile')
Response = namedtuple('Response', 'status reason headers body')


class UnconsumedResponseError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous response body not consumed: {!r}'.format(body)
        )


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
    line_parts = line.split(' ', 2)
    if len(line_parts) != 3:
        raise ParseError('Bad Status Line')
    (protocol, status_str, reason) = line_parts

    # Validate protocol:
    if protocol != 'HTTP/1.1':
        raise ParseError('HTTP Version Not Supported')

    # Convent status into an int, validate:
    try:
        status = int(status_str)
    except ValueError:
        raise ParseError('Bad Status Code')
    if not (100 <= status <= 599):
        raise ParseError('Invalid Status Code')

    # Validate reason:
    if not reason:
        raise ParseError('Empty Reason')
    if reason.strip() != reason:
        raise ParseError('Extraneous Whitespace In Reason')

    # Return only (status, reason) as protocol isn't interesting:
    return (status, reason)


def read_response(rfile, method):
    (status, reason) = parse_status(read_line(rfile))
    headers = read_headers(rfile)
    if 'content-length' in headers and method != 'HEAD':
        body = Input(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = ChunkedInput(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


class Client:
    default_port = 80

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = (self.default_port if port is None else port)
        self.conn = None
        self.response_body = None  # Previous Input or ChunkedInput

    def create_socket(self):
        return socket.create_connection((self.hostname, self.port))

    def connect(self):
        if self.conn is None:
            sock = self.create_socket()
            (rfile, wfile) = makefiles(sock)
            self.conn = Connection(sock, rfile, wfile)
        return self.conn

    def close(self):
        self.response_body = None
        if self.conn is not None:
            self.conn.rfile.close()
            self.conn.wfile.close()
            try:
                self.conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.conn.sock.close()
            self.conn = None

    def request(self, method, uri, headers=None, body=None):
        if self.response_body and not self.response_body.closed:
            raise UnconsumedResponseError(self.response_body)
        if headers is None:
            headers = {}
        validate_request(method, uri, headers, body)
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
    default_port = 443

    def __init__(self, hostname, port, ssl_ctx, check_hostname=True):
        super().__init__(hostname, port)
        self.ssl_ctx = ssl_ctx
        self.check_hostname = check_hostname

    def create_socket(self):
        sock = self.ssl_ctx.wrap_socket(
            socket.create_connection((self.hostname, self.port)),
            server_hostname=self.hostname
        )
        peercert = sock.getpeercert()
        try:
            if self.check_hostname:
                ssl.match_hostname(peercert, self.hostname)
            self.handle_ssl_connection(sock, peercert)
        except Exception:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            raise
        return sock

    def handle_ssl_connection(self, sock, peercert):
        pass
