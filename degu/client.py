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

from .base import (
    TYPE_ERROR,
    default_bodies,
    Body,
    BodyIter,
    ChunkedBody,
    ChunkedBodyIter,
    makefiles,
    read_preamble,
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


def build_client_sslctx(sslconfig):
    """
    Build an ``ssl.SSLContext`` appropriately configured for client use.

    For example:

    >>> sslconfig = {
    ...     'check_hostname': False,
    ...     'ca_file': '/my/server.ca',
    ...     'cert_file': '/my/client.cert',
    ...     'key_file': '/my/client.key',
    ... }
    >>> sslctx = build_client_sslctx(sslconfig)  #doctest: +SKIP

    """
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if not isinstance(sslconfig, dict):
        raise TypeError(
            TYPE_ERROR.format('sslconfig', dict, type(sslconfig), sslconfig)
        )

    # In typical Degu P2P usage, hostname checking is meaningless because we
    # wont be trusting centralized certificate authorities, and will typically
    # only connect to servers via their IP address; however, it's still prudent
    # to make *check_hostname* default to True:
    check_hostname = sslconfig.get('check_hostname', True)
    if not isinstance(check_hostname, bool):
        raise TypeError(TYPE_ERROR.format(
            "sslconfig['check_hostname']", bool, type(check_hostname), check_hostname
        ))

    # Don't allow 'key_file' to be provided without the 'cert_file':
    if 'key_file' in sslconfig and 'cert_file' not in sslconfig:
        raise ValueError(
            "sslconfig['key_file'] provided without sslconfig['cert_file']"
        )

    # For safety and clarity, force all paths to be absolute, normalized paths:
    for key in ('ca_file', 'ca_path', 'cert_file', 'key_file'):
        if key in sslconfig:
            value = sslconfig[key]
            if value != path.abspath(value):
                raise ValueError(
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(
                        key, value
                    )
                )

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    sslctx.options |= ssl.OP_NO_COMPRESSION
    if 'ca_file' in sslconfig or 'ca_path' in sslconfig:
        sslctx.load_verify_locations(
            cafile=sslconfig.get('ca_file'),
            capath=sslconfig.get('ca_path'),
        )
    else:
        if check_hostname is not True:
            raise ValueError(
                'check_hostname must be True when using default verify paths'
            )
        sslctx.set_default_verify_paths()
    if 'cert_file' in sslconfig:
        sslctx.load_cert_chain(sslconfig['cert_file'],
            keyfile=sslconfig.get('key_file')
        )
    sslctx.check_hostname = check_hostname
    return sslctx


def validate_client_sslctx(sslctx):
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if isinstance(sslctx, dict):
        sslctx = build_client_sslctx(sslctx)

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
    # FIXME: Perhaps relax this a bit, only require the method to be uppercase?
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ValueError('invalid method: {!r}'.format(method))

    # Ensure all header keys are lowercase:
    if not all([key.islower() for key in headers]):
        for key in sorted(headers):  # Sorted for deterministic unit testing
            if not key.islower():
                raise ValueError('non-casefolded header name: {!r}'.format(key))
        raise Exception('should not be reached')

    # A body of None is the most common, so check this case first:
    if body is None:
        if 'content-length' in headers:
            raise ValueError(
                "cannot include 'content-length' when body is None"
            )
        if 'transfer-encoding' in headers:
            raise ValueError(
                "cannot include 'transfer-encoding' when body is None"
            )
        return

    # Check body type, set content-length or transfer-encoding header as needed:
    if isinstance(body, (bytes, bytearray)): 
        headers['content-length'] = len(body)
        if 'transfer-encoding' in headers:
            raise ValueError(
                "cannot include 'transfer-encoding' with length-encoded body"
            )
    elif isinstance(body, (Body, BodyIter)):
        headers['content-length'] = body.content_length
        if 'transfer-encoding' in headers:
            raise ValueError(
                "cannot include 'transfer-encoding' with length-encoded body"
            )
    elif isinstance(body, (ChunkedBody, ChunkedBodyIter)):
        headers['transfer-encoding'] = 'chunked'
        if 'content-length' in headers:
            raise ValueError(
                "cannot include 'content-length' with chunk-encoded body"
            )
    else:
        raise TypeError('bad request body type: {!r}'.format(type(body)))

    # A body is only allowed when the request method is PUT or POST:
    if method not in {'PUT', 'POST'}:
        raise ValueError('cannot include body in a {} request'.format(method))


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
    # For performance, store these attributes in local variables:
    write = wfile.write
    flush = wfile.flush

    # Write the first line:
    total = write('{} {} HTTP/1.1\r\n'.format(method, uri).encode())

    # Write the header lines:
    header_lines = ['{}: {}\r\n'.format(*kv) for kv in headers.items()]
    header_lines.sort()
    total += write(''.join(header_lines).encode())

    # Write the final preamble CRLF terminator:
    total += write(b'\r\n')

    # Write the body:
    if body is None:
        flush()
    elif isinstance(body, (bytes, bytearray)):
        total += write(body)
        flush()
    else:
        total += body.write_to(wfile)
    return total


def read_response(rfile, method):
    (status_line, headers) = read_preamble(rfile)
    (status, reason) = parse_status(status_line)
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

    def __init__(self, sock, base_headers, bodies):
        assert base_headers is None or isinstance(base_headers, dict)
        self.sock = sock
        self.base_headers = base_headers
        self.bodies = bodies
        (self.rfile, self.wfile) = makefiles(sock)
        self.response_body = None  # Previous Body or ChunkedBody or None

    def __del__(self):
        self.close()

    @property
    def closed(self):
        return self.sock is None

    def close(self):
        # We sometimes get a TypeError when a connection is GC'ed just prior to
        # a script exiting:
        # Exception ignored in: <bound method Connection.__del__ of <degu.client.Connection object at 0x7f6e8ca10ef0>>
        # Traceback (most recent call last):
        # File "/usr/lib/python3/dist-packages/degu/client.py", line 252, in __del__
        # File "/usr/lib/python3/dist-packages/degu/client.py", line 262, in close
        # TypeError: an integer is required (got type NoneType)
        #
        self.response_body = None  # Always deference previous response_body
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except (OSError, TypeError):
                pass
            self.sock = None

    def request(self, method, uri, headers, body):
        assert isinstance(headers, dict)
        if self.sock is None:
            raise ClosedConnectionError(self)
        try:
            if not (self.response_body is None or self.response_body.closed):
                raise UnconsumedResponseError(self.response_body)
            if isinstance(body, io.BufferedReader):
                if 'content-length' in headers:
                    content_length = headers['content-length']
                else:
                    content_length = os.stat(body.fileno()).st_size
                body = Body(body, content_length)
            validate_request(method, uri, headers, body)
            if self.base_headers:
                headers.update(self.base_headers)
            write_request(self.wfile, method, uri, headers, body)
            response = read_response(self.rfile, method)
            self.response_body = response.body
            return response
        except Exception:
            self.close()
            raise


def build_default_client_options():
    return {
        'base_headers': None,
        'bodies': default_bodies,
        'timeout': 90,
        'Connection': Connection,
    }


def validate_client_options(**options):
    result = build_default_client_options()
    result.update(options)

    # base_headers:
    base_headers = result['base_headers']
    if base_headers is not None:
        if not isinstance(base_headers, dict):
            raise TypeError(TYPE_ERROR.format(
                'base_headers', dict, type(base_headers), base_headers
            ))
        for key in base_headers:
            assert isinstance(key, str)
            if not key.islower():
                raise ValueError('non-casefolded header name: {!r}'.format(key))
        for key in ('content-length', 'transfer-encoding'):
            if key in base_headers:
                raise ValueError('base_headers cannot include {!r}'.format(key))

    # bodies:
    bodies = result['bodies']
    for name in ('Body', 'BodyIter', 'ChunkedBody', 'ChunkedBodyIter'):
        if not hasattr(bodies, name):
            raise TypeError('bodies is missing {!r} attribute'.format(name))
        attr = getattr(bodies, name)
        if not callable(attr):
            raise TypeError('bodies.{} is not callable: {!r}'.format(name, attr))

    # timeout:
    timeout = result['timeout']
    if timeout is not None:
        if not isinstance(timeout, (int, float)):
            raise TypeError(
                TYPE_ERROR.format('timeout', (int, float), type(timeout), timeout)
            )
        if not (timeout > 0):
            raise ValueError(
                'timeout must be > 0; got {!r}'.format(timeout)
            )

    # Connection:
    Connection = result['Connection']
    if not callable(Connection):
        raise TypeError(
            'Connection is not callable: {!r}'.format(Connection)
        )

    return result


class Client:
    """
    Represents an HTTP server to which Degu can make client connections.

    A `Client` instance is stateless and thread-safe.
    """

    def __init__(self, address, **options):
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
        options = validate_client_options(**options)
        self._Connection = options['Connection']
        self._base_headers = options['base_headers']
        self._bodies = options['bodies']
        self._options = options

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.address)

    @property
    def options(self):
        return self._options.copy()

    def create_socket(self):
        if self.family is None:
            return socket.create_connection(self.address)
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.connect(self.address)
        return sock

    def connect(self):
        return self._Connection(self.create_socket(),
            self._base_headers, self._bodies
        )


class SSLClient(Client):
    """
    Represents an HTTPS server to which Degu can make client connections.

    An `SSLClient` instance is stateless and thread-safe.
    """

    def __init__(self, sslctx, address, **options):
        self.sslctx = validate_client_sslctx(sslctx)
        super().__init__(address, **options)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address
        )

    def create_socket(self):
        sock = super().create_socket()
        return self.sslctx.wrap_socket(sock,
            server_hostname=self.server_hostname,
        )

