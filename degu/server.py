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
HTTP server.
"""

import socket
import logging
import threading
import os

from .base import (
    _TYPE_ERROR,
    _makefiles,
    _isconsumed,
    bodies,
)


log = logging.getLogger()


class UnconsumedRequestError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous request body not consumed: {!r}'.format(body)
        )


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
                'cannot include ca_file/ca_path allow_unauthenticated_clients'
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

    # Check the options:
    if not (sslctx.options & ssl.OP_NO_COMPRESSION):
        raise ValueError('sslctx.options must include ssl.OP_NO_COMPRESSION')
    if not (sslctx.options & ssl.OP_SINGLE_ECDH_USE):
        raise ValueError('sslctx.options must include ssl.OP_SINGLE_ECDH_USE')
    if not (sslctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE):
        raise ValueError('sslctx.options must include ssl.OP_CIPHER_SERVER_PREFERENCE')

    return sslctx


def _handle_requests(app, sock, max_requests, session, bodies=bodies):
    (reader, writer) = _makefiles(sock)
    assert session['requests'] == 0
    for count in range(1, max_requests + 1):
        request = reader.read_request()
        (status, reason, headers, body) = app(session, request, bodies)

        # Make sure application fully consumed request body:
        if not _isconsumed(request.body):
            raise UnconsumedRequestError(request.body)

        # Make sure HEAD requests are properly handled:
        if request.method == 'HEAD':
            if body is not None:
                raise TypeError(
                    'response body must be None when request method is HEAD'
                )
            if 200 <= status < 300:
                if 'content-length' in headers:
                    if 'transfer-encoding' in headers:
                        raise ValueError(
                            'cannot have both content-length and transfer-encoding headers'
                        )
                elif headers.get('transfer-encoding') != 'chunked':
                    raise ValueError(
                        'response to HEAD request must include content-length or transfer-encoding'
                    )

        # Write response:
        #sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
        writer.write_response(status, reason, headers, body)
        #sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)

        # Update session counter:
        session['requests'] = count

        # Possibly close the connection:
        if status >= 400 and status not in {404, 409, 412}:
            log.warning('closing connection to %r after %d %r',
                session['client'], status, reason
            )
            break

    # Make sure sndbuf gets flushed:
    sock.close()


class Server:
    _allowed_options = ('max_connections', 'max_requests', 'timeout')

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
        self.on_connect = on_connect

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
        self.max_connections = options.get('max_connections', 25)
        self.max_requests = options.get('max_requests', 500)
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
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.address, self.app
        )

    def serve_forever(self):
        semaphore = threading.BoundedSemaphore(self.max_connections)
        max_requests = self.max_requests
        timeout = self.timeout
        listensock = self.sock
        worker = self._worker
        while True:
            (sock, address) = listensock.accept()
            # Denial of Service note: when we already have max_connections, we
            # should aggressively rate-limit the handling of new connections, so
            # that's why we use `timeout=2` rather than `blocking=False`:
            if semaphore.acquire(timeout=2) is True:
                sock.settimeout(timeout)
                thread = threading.Thread(
                    target=worker,
                    args=(semaphore, max_requests, sock, address),
                    daemon=True
                )
                thread.start()
            else:
                log.warning('Rejecting connection from %r', address)
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _worker(self, semaphore, max_requests, sock, address):
        session = {'client': address, 'requests': 0}
        log.info('Connection from %r', address)
        try:
            self._handler(sock, max_requests, session)
        except OSError as e:
            log.info('Handled %d requests from %r: %r', 
                session.get('requests'), address, e
            )
        except:
            log.exception('Client: %r', address)
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            semaphore.release()

    def _handler(self, sock, max_requests, session):
        if self.on_connect is None or self.on_connect(session, sock) is True:
            _handle_requests(self.app, sock, max_requests, session)
        else:
            log.warning('rejecting connection: %r', session['client'])


class SSLServer(Server):
    def __init__(self, sslctx, address, app, **options):
        self.sslctx = _validate_server_sslctx(sslctx)
        super().__init__(address, app, **options)

    def __repr__(self):
        return '{}({!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address, self.app
        )

    def _handler(self, sock, max_requests, session):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        session.update({
            'ssl_cipher': sock.cipher(),
            'ssl_compression': sock.compression(),
        })
        super()._handler(sock, max_requests, session)

