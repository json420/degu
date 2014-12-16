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
import os

from .base import bodies as default_bodies
from .base import _TYPE_ERROR, _makefiles, _read_preamble, format_request_preamble


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
    Build an `ssl.SSLContext` appropriately configured for client-side use.

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
            _TYPE_ERROR.format('sslconfig', dict, type(sslconfig), sslconfig)
        )

    # In typical Degu P2P usage, hostname checking is meaningless because we
    # wont be trusting centralized certificate authorities, and will typically
    # only connect to servers via their IP address; however, it's still prudent
    # to make *check_hostname* default to True:
    check_hostname = sslconfig.get('check_hostname', True)
    if not isinstance(check_hostname, bool):
        raise TypeError(_TYPE_ERROR.format(
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
            if value != os.path.abspath(value):
                raise ValueError(
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(
                        key, value
                    )
                )

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.set_ciphers(
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
    )
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


def _validate_client_sslctx(sslctx):
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


def _validate_request(bodies, method, uri, headers, body):
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
                "headers['content-length'] included when body is None"
            )
        if 'transfer-encoding' in headers:
            raise ValueError(
                "headers['transfer-encoding'] included when body is None"
            )
        return

    # Check body type, set content-length or transfer-encoding header as needed:
    if isinstance(body, (bytes, bytearray, bodies.Body, bodies.BodyIter)):
        length = len(body)
        if headers.setdefault('content-length', length) != length:
            raise ValueError(
                "headers['content-length'] != len(body): {!r} != {!r}".format(
                    headers['content-length'], length
                )
            )
        if 'transfer-encoding' in headers:
            raise ValueError(
                "headers['transfer-encoding'] with length-encoded body"
            )
    elif isinstance(body, (bodies.ChunkedBody, bodies.ChunkedBodyIter)):
        if headers.setdefault('transfer-encoding', 'chunked') != 'chunked':
            raise ValueError(
                "headers['transfer-encoding'] is invalid: {!r}".format(
                    headers['transfer-encoding']
                )
            )
        if 'content-length' in headers:
            raise ValueError(
                "headers['content-length'] with chunk-encoded body"
            )
    else:
        raise TypeError('bad request body type: {!r}'.format(type(body)))

    # A body is only allowed when the request method is PUT or POST:
    if method not in {'PUT', 'POST'}:
        raise ValueError('cannot include body in a {} request'.format(method))


def _parse_status(line):
    """
    Parse the status line.

    The return value will be a ``(status, reason)`` tuple, and the status will
    be converted into an integer:

    >>> _parse_status('HTTP/1.1 404 Not Found')
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


def _write_request(wfile, method, uri, headers, body):
    preamble = format_request_preamble(method, uri, headers)
    if body is None:
        total = wfile.write(preamble)
        wfile.flush()
    elif isinstance(body, (bytes, bytearray)):
        total = wfile.write(preamble + body)
        wfile.flush()
    else:
        total = wfile.write(preamble)
        total += body.write_to(wfile)
    return total


def _read_response(rfile, bodies, method):
    (status_line, headers) = _read_preamble(rfile)
    (status, reason) = _parse_status(status_line)
    if method == 'HEAD':
        body = None
    elif 'content-length' in headers:
        body = bodies.Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = bodies.ChunkedBody(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


class Connection:
    """
    Provides an HTTP client request API atop an arbitrary socket connection.

    A `Connection` is stateful and is *not* thread-safe.
    """

    __slots__ = (
        'sock', 'base_headers', 'bodies', '_rfile', '_wfile', '_response_body'
    )

    def __init__(self, sock, base_headers, bodies):
        self.sock = sock
        self.base_headers = base_headers
        self.bodies = bodies
        (self._rfile, self._wfile) = _makefiles(sock)
        self._response_body = None  # Previous Body(), ChunkedBody(), or None

    def __del__(self):
        self.close()

    @property
    def closed(self):
        return self.sock is None

    def close(self):
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except (OSError, TypeError):
                pass
            self.sock = None
            self._rfile = None
            self._wfile = None
            self._response_body = None

    def request(self, method, uri, headers, body):
        if self.sock is None:
            raise ClosedConnectionError(self)
        try:
            if not (self._response_body is None or self._response_body.closed):
                raise UnconsumedResponseError(self._response_body)
            if self.base_headers:
                headers.update(self.base_headers)
            _validate_request(self.bodies, method, uri, headers, body)
            _write_request(self._wfile, method, uri, headers, body)
            response = _read_response(self._rfile, self.bodies, method)
            self._response_body = response.body
            return response
        except Exception:
            self.close()
            raise

    def put(self, uri, headers, body):
        return self.request('PUT', uri, headers, body)

    def post(self, uri, headers, body):
        return self.request('POST', uri, headers, body)

    def get(self, uri, headers):
        return self.request('GET', uri, headers, None)

    def head(self, uri, headers):
        return self.request('HEAD', uri, headers, None)

    def delete(self, uri, headers):
        return self.request('DELETE', uri, headers, None)

    def get_range(self, uri, headers, start, stop):
        assert isinstance(start, int)
        assert isinstance(stop, int)
        assert 0 <= start < stop
        headers['range'] = 'bytes={}-{}'.format(start, stop - 1)
        response = self.request('GET', uri, headers, None)
        assert isinstance(response.body, self.bodies.Body)
        assert response.body.content_length == stop - start
        return response


def _build_host(default_port, host, port, *extra):
    """
    Build value for HTTP "host" header.

    For example, for a DNS *host* name:

    >>> _build_host(80, 'en.wikipedia.org', 80)
    'en.wikipedia.org'
    >>> _build_host(80, 'en.wikipedia.org', 1234)
    'en.wikipedia.org:1234'

    And for an IPv4 literal *host*:

    >>> _build_host(80, '208.80.154.224', 80)
    '208.80.154.224'
    >>> _build_host(80, '208.80.154.224', 1234)
    '208.80.154.224:1234'

    And for an IPv6 literal *host*:

    >>> _build_host(80, '2620:0:861:ed1a::1', 80, 0, 0)
    '[2620:0:861:ed1a::1]'
    >>> _build_host(80, '2620:0:861:ed1a::1', 1234, 0, 0)
    '[2620:0:861:ed1a::1]:1234'

    """
    if not isinstance(default_port, int):
        raise TypeError(
            _TYPE_ERROR.format('default_port', int, type(default_port), default_port)
        )
    if not isinstance(host, str):
        raise TypeError(
            _TYPE_ERROR.format('host', str, type(host), host)
        )
    if not isinstance(port, int):
        raise TypeError(
            _TYPE_ERROR.format('port', int, type(port), port)
        )
    for arg in extra:
        assert isinstance(arg, int)
    if ':' in host:
        host = '[{}]'.format(host)
    if port == default_port:
        return host
    return '{}:{}'.format(host, port)


class Client:
    """
    Specifies where an HTTP server is, and how to connect to it.

    >>> client = Client(('en.wikipedia.org', 80))

    A Client is stateless and thread-safe, does not itself reference any socket
    resources.

    To make HTTP requests, create a Connection using Client.connect().
    """

    _default_port = 80  # Needed to contruct the default host header
    _allowed_options = ('host', 'timeout', 'bodies', 'on_connect')

    def __init__(self, address, **options):
        # address:
        if isinstance(address, tuple):  
            if len(address) == 4:
                self._family = socket.AF_INET6
            elif len(address) == 2:
                self._family = None
            else:
                raise ValueError(
                    'address: must have 2 or 4 items; got {!r}'.format(address)
                )
            host = _build_host(self.__class__._default_port, *address)
        elif isinstance(address, (str, bytes)):
            self._family = socket.AF_UNIX
            host = None
            if isinstance(address, str) and os.path.abspath(address) != address:
                raise ValueError(
                    'address: bad socket filename: {!r}'.format(address)
                )
        else:
            raise TypeError(
                _TYPE_ERROR.format('address', (tuple, str, bytes), type(address), address)
            )
        self.address = address

        # options:
        if not set(options).issubset(self.__class__._allowed_options):
            cls = self.__class__
            unsupported = sorted(set(options) - set(cls._allowed_options))
            raise TypeError(
                'unsupported {} **options: {}'.format(
                    cls.__name__, ', '.join(unsupported)
                )
            )
        self.options = options
        self.bodies = options.get('bodies', default_bodies)
        self.host = options.get('host', host)
        self.timeout = options.get('timeout', 90)
        self.on_connect = options.get('on_connect')
        assert self.host is None or isinstance(self.host, str)
        assert self.timeout is None or isinstance(self.timeout, (int, float))
        if not (self.on_connect is None or callable(self.on_connect)):
            raise TypeError(
                'on_connect: not callable: {!r}'.format(self.on_connect)
            )

        # Build _base_headers:
        self._base_headers = ({'host': self.host} if self.host else None)

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.address)

    def create_socket(self):
        if self._family is None:
            return socket.create_connection(self.address, timeout=self.timeout)
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.address)
        return sock

    def connect(self, bodies=None):
        if bodies is None:
            bodies = self.bodies
        conn = Connection(self.create_socket(), self._base_headers, bodies)
        if self.on_connect is None or self.on_connect(conn) is True:
            return conn
        raise ValueError('on_connect() did not return True')


class SSLClient(Client):
    """
    Specifies where an HTTPS server is, and how to connect to it.

    >>> sslclient = SSLClient({}, ('www.wikipedia.org', 443))

    An SSLClient is stateless and thread-safe, does not itself reference any
    socket resources.

    To make HTTP requests, create a Connection using Client.connect().
    """

    _default_port = 443  # Needed to contruct the default host header
    _allowed_options = Client._allowed_options + ('ssl_host',)

    def __init__(self, sslctx, address, **options):
        self.sslctx = _validate_client_sslctx(sslctx)
        super().__init__(address, **options)
        ssl_host = (address[0] if isinstance(address, tuple) else None)
        self.ssl_host = options.get('ssl_host', ssl_host)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address
        )

    def create_socket(self):
        sock = super().create_socket()
        return self.sslctx.wrap_socket(sock, server_hostname=self.ssl_host)

