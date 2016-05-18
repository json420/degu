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
HTTP client.
"""

import os
import socket

from .base import Connection, Response, _TYPE_ERROR


__all__ = ('Client', 'SSLClient', 'Connection', 'Response')


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

    _default_port = 80  # Needed to construct the default host header
    _options = ('host', 'authorization', 'timeout', 'on_connect')
    __slots__ = ('address', 'options', '_family', 'base_headers') + _options

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
        if not set(options).issubset(self.__class__._options):
            unsupported = sorted(set(options) - set(self.__class__._options))
            raise TypeError(
                'unsupported {}() **options: {}'.format(
                    self.__class__.__name__, ', '.join(unsupported)
                )
            )
        self.options = options
        self.host = options.get('host', host)
        self.authorization = options.get('authorization')
        self.timeout = options.get('timeout', 65)
        self.on_connect = options.get('on_connect')
        assert self.host is None or isinstance(self.host, str)
        assert self.authorization is None or isinstance(self.authorization, str)
        assert self.timeout is None or isinstance(self.timeout, (int, float))
        if not (self.on_connect is None or callable(self.on_connect)):
            raise TypeError(
                'on_connect: not callable: {!r}'.format(self.on_connect)
            )

        # Build _base_headers:
        headers = []
        if self.authorization:
            headers.append(('authorization', self.authorization))
        if self.host:
            headers.append(('host', self.host))
        self.base_headers = (tuple(headers) if headers else None)

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.address)

    def set_base_header(self, key, value):
        assert type(key) is str and key.islower()
        assert value is None or type(value) is str
        existing = self.base_headers
        new = ({} if existing is None else dict(existing))
        if value is None:
            new.pop(key, None)
        else:
            new[key] = value
        self.base_headers = (tuple(sorted(new.items())) if new else None)

    def create_socket(self):
        if self._family is None:
            return socket.create_connection(self.address, timeout=self.timeout)
        sock = socket.socket(self._family, socket.SOCK_STREAM)
        if self._family == socket.AF_UNIX:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        sock.settimeout(self.timeout)
        sock.connect(self.address)
        return sock

    def connect(self):
        sock = self.create_socket()
        conn = Connection(sock, self.base_headers)
        if self.on_connect is None or self.on_connect(conn) is True:
            return conn
        conn.close()
        raise ValueError('on_connect() did not return True')


class SSLClient(Client):
    """
    Specifies where an HTTPS server is, and how to connect to it.

    >>> sslclient = SSLClient({}, ('www.wikipedia.org', 443))

    An SSLClient is stateless and thread-safe, does not itself reference any
    socket resources.

    To make HTTP requests, create a Connection using Client.connect().
    """

    _default_port = 443  # Needed to construct the default host header
    _options = Client._options + ('ssl_host',)
    __slots__ = ('sslctx', 'ssl_host')

    def __init__(self, sslctx, address, **options):
        self.sslctx = _validate_client_sslctx(sslctx)
        super().__init__(address, **options)
        ssl_host = (address[0] if isinstance(address, tuple) else None)
        self.ssl_host = options.get('ssl_host', ssl_host)

    def __repr__(self):
        return '{}(<sslctx>, {!r})'.format(
            self.__class__.__name__, self.address
        )

    def create_socket(self):
        sock = super().create_socket()
        return self.sslctx.wrap_socket(sock, server_hostname=self.ssl_host)

