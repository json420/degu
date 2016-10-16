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
HTTP server.
"""

import os
import socket
import threading
import struct
import logging

from .base import Session, Request, _handle_requests, _TYPE_ERROR


__all__ = ('Server', 'SSLServer', 'Session', 'Request')
log = logging.getLogger(__name__)


def build_server_sslctx(sslconfig):
    """
    Build an `ssl.SSLContext` appropriately configured for server-side use.

    For example:

    >>> sslconfig = {
    ...     'cert_file': '/my/server.cert',
    ...     'key_file': '/my/server.key',
    ...     'ca_file': '/my/client.ca',
    ... }
    >>> sslctx = build_server_sslctx(sslconfig)  #doctest: +SKIP

    """
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if not isinstance(sslconfig, dict):
        raise TypeError(
            _TYPE_ERROR.format('sslconfig', dict, type(sslconfig), sslconfig)
        )

    # For safety and clarity, force all paths to be absolute, normalized paths:
    for key in ('cert_file', 'key_file', 'ca_file', 'ca_path'):
        if key in sslconfig:
            value = sslconfig[key]
            if value != os.path.abspath(value):
                raise ValueError(
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(
                        key, value
                    )
                )

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslctx.set_ciphers(
        'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
    )
    sslctx.set_ecdh_curve('secp384r1')
    sslctx.options |= ssl.OP_NO_COMPRESSION
    sslctx.options |= ssl.OP_SINGLE_ECDH_USE
    sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    sslctx.load_cert_chain(sslconfig['cert_file'], sslconfig['key_file'])
    if 'allow_unauthenticated_clients' in sslconfig:
        if sslconfig['allow_unauthenticated_clients'] is not True:
            raise ValueError(
                'True is only allowed value for allow_unauthenticated_clients'
            )
        if {'ca_file', 'ca_path'}.intersection(sslconfig):
            raise ValueError(
                'ca_file/ca_path with allow_unauthenticated_clients'
            )
        return sslctx
    if not {'ca_file', 'ca_path'}.intersection(sslconfig):
        raise ValueError(
            'must include ca_file or ca_path (or allow_unauthenticated_clients)'
        )
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.load_verify_locations(
        cafile=sslconfig.get('ca_file'),
        capath=sslconfig.get('ca_path'),
    )
    return sslctx


def _validate_server_sslctx(sslctx):
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if isinstance(sslctx, dict):
        sslctx = build_server_sslctx(sslctx)

    if not isinstance(sslctx, ssl.SSLContext):
        raise TypeError('sslctx must be an ssl.SSLContext')
    if sslctx.protocol != ssl.PROTOCOL_TLSv1_2:
        raise ValueError('sslctx.protocol must be ssl.PROTOCOL_TLSv1_2')

    # We consider ssl.CERT_OPTIONAL to be a bad grey area:
    if sslctx.verify_mode == ssl.CERT_OPTIONAL:
        raise ValueError('sslctx.verify_mode cannot be ssl.CERT_OPTIONAL')
    assert sslctx.verify_mode in (ssl.CERT_REQUIRED, ssl.CERT_NONE)
    if sslctx.verify_mode != ssl.CERT_REQUIRED:
        log.warning('Security concern: sslctx allows unauthenticated clients!')

    # Check the options:
    if not (sslctx.options & ssl.OP_NO_COMPRESSION):
        raise ValueError('sslctx.options must include ssl.OP_NO_COMPRESSION')
    if not (sslctx.options & ssl.OP_SINGLE_ECDH_USE):
        raise ValueError('sslctx.options must include ssl.OP_SINGLE_ECDH_USE')
    if not (sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE):
        raise ValueError('sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE')

    return sslctx


def _fq_name(app):
    if hasattr(app, '__qualname__'):
        return '{}.{}'.format(app.__module__, app.__qualname__)
    cls = app.__class__
    return '{}.{}(<...>)'.format(cls.__module__, cls.__qualname__)


def _get_credentials(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    size = struct.calcsize('3i')
    data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    return struct.unpack('3i', data)


class Server:
    _options = ('max_connections', 'max_requests', 'timeout')
    __slots__ = ('address', 'app', 'options', 'sock') + _options

    def __init__(self, address, app, **options):
        # address:
        if isinstance(address, tuple):  
            if len(address) == 4:
                family = socket.AF_INET6
            elif len(address) == 2:
                family = socket.AF_INET
            else:
                raise ValueError(
                    'address: must have 2 or 4 items; got {!r}'.format(address)
                )
        elif isinstance(address, str):
            if os.path.abspath(address) != address:
                raise ValueError(
                    'address: bad socket filename: {!r}'.format(address)
                )
            family = socket.AF_UNIX
        elif isinstance(address, bytes):
            family = socket.AF_UNIX
        else:
            raise TypeError(
                _TYPE_ERROR.format('address', (tuple, str, bytes), type(address), address)
            )

        # app:
        if not callable(app):
            raise TypeError('app: not callable: {!r}'.format(app))
        on_connect = getattr(app, 'on_connect', None)
        if not (on_connect is None or callable(on_connect)):
            raise TypeError('app.on_connect: not callable: {!r}'.format(app))
        self.app = app

        # options:
        if not set(options).issubset(self.__class__._options):
            unsupported = sorted(set(options) - set(self.__class__._options))
            raise TypeError(
                'unsupported {}() **options: {}'.format(
                    self.__class__.__name__, ', '.join(unsupported)
                )
            )
        self.options = options
        self.max_connections = options.get('max_connections', 50)
        self.max_requests = options.get('max_requests', 1000)
        self.timeout = options.get('timeout', 30)
        assert isinstance(self.max_connections, int) and self.max_connections > 0
        assert isinstance(self.max_requests, int) and self.max_requests > 0 
        assert isinstance(self.timeout, (int, float)) and self.timeout > 0

        # Listen...
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(address)
        self.address = self.sock.getsockname()
        self.sock.listen(5)

    def __repr__(self):
        return '{}({!r}, {})'.format(
            self.__class__.__name__, self.address, _fq_name(self.app)
        )

    def serve_forever(self):
        try:
            self._serve_forever()
        finally:
            self.sock.close()

    def _serve_forever(self):
        log.info('Starting Degu %s @ %r', self.__class__.__name__, self.address)
        log.info('[timeout=%r, max_connections=%r, max_requests=%r]',
            self.timeout, self.max_connections, self.max_requests
        )
        listensock = self.sock
        unix = (True if listensock.family == socket.AF_UNIX else False)
        semaphore = threading.BoundedSemaphore(self.max_connections)
        timeout = self.timeout
        max_requests = self.max_requests
        worker = self._worker
        while True:
            (sock, address) = listensock.accept()
            # Denial of Service note: when we already have max_connections, we
            # should aggressively rate-limit the handling of new connections, so
            # that's why we use `timeout=2` rather than `blocking=False`:
            if semaphore.acquire(timeout=2) is True:
                sock.settimeout(timeout)
                credentials = (_get_credentials(sock) if unix is True else None)
                session = Session(address, credentials, max_requests)
                thread = threading.Thread(
                    target=worker,
                    args=(semaphore, session, sock),
                    daemon=True,
                )
                thread.start()
            else:
                log.warning('Too many connections, rejecting %r', address)
                sock.close()

    def _serve_one(self):
        unix = (True if self.sock.family == socket.AF_UNIX else False)
        (sock, address) = self.sock.accept()
        sock.settimeout(self.timeout)
        credentials = (_get_credentials(sock) if unix is True else None)
        session = Session(address, credentials, self.max_requests)
        self._worker(None, session, sock)

    def _worker(self, semaphore, session, sock):
        try:
            log.info('+ %s New connection', session)
            self._handle_connection(session, sock)
        except (socket.timeout, ConnectionError) as e:
            log.info('- %s Handled %d requests: %r',
                session, session.requests, e
            )
        except:
            log.exception('- %s Error after handling %d requests:',
                session, session.requests
            )
        finally:
            sock.close()
            if semaphore is not None:
                semaphore.release()

    def _handle_connection(self, session, sock):
        on_connect = getattr(self.app, 'on_connect', None)
        if on_connect is None or on_connect(session, sock) is True:
            _handle_requests(self.app, session, sock)
            sock.close()
            log.info('- %s Handled %d requests: %s',
                session, session.requests, session.message
            )
        else:
            log.warning('- %s Rejected by app.on_connect()', session)


class SSLServer(Server):
    __slots__ = ('sslctx',)

    def __init__(self, sslctx, address, app, **options):
        self.sslctx = _validate_server_sslctx(sslctx)
        super().__init__(address, app, **options)

    def __repr__(self):
        return '{}(<sslctx>, {!r}, {})'.format(
            self.__class__.__name__, self.address, _fq_name(self.app)
        )

    def _handle_connection(self, session, sock):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        super()._handle_connection(session, sock)

