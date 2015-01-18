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

from .base import bodies as default_bodies
from .base import (
    _TYPE_ERROR,
    _makefiles,
    _read_request_preamble,
    format_response_preamble,
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


def _read_request(rfile, bodies):
    (method, uri, headers) = _read_request_preamble(rfile)

    uri_parts = uri.split('?')
    if len(uri_parts) == 2:
        (path_str, query) = uri_parts
    elif len(uri_parts) == 1:
        (path_str, query) = (uri_parts[0], None)
    else:
        raise ValueError('bad request uri: {!r}'.format(uri))
    if path_str[:1] != '/' or '//' in path_str:
        raise ValueError('bad request path: {!r}'.format(path_str))
    path = ([] if path_str == '/' else path_str[1:].split('/'))

    # Only one dictionary lookup for content-length:
    content_length = headers.get('content-length')

    # Build request body:
    if content_length is not None:
        # Hack for compatibility with the CouchDB replicator, which annoyingly
        # sends a {'content-length': 0} header with all GET and HEAD requests:
        if method in {'GET', 'HEAD'} and content_length == 0:
            del headers['content-length']
        else:
            body = bodies.Body(rfile, content_length)
    elif 'transfer-encoding' in headers:
        body = bodies.ChunkedBody(rfile)
    else:
        body = None
    if body is not None and method not in {'POST', 'PUT'}:
        raise ValueError(
            'Request body with wrong method: {!r}'.format(method)
        )

    # Return the RGI request argument:
    return {
        'method': method,
        'uri': uri,
        'script': [],
        'path': path,
        'query': query,
        'headers': headers,
        'body': body,
    }


def _write_response(wfile, status, reason, headers, body):
    preamble = format_response_preamble(status, reason, headers)
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


def _handle_requests(app, sock, max_requests, session, bodies):
    (rfile, wfile) = _makefiles(sock, bodies)
    assert session['requests'] == 0
    requests = 0
    while _handle_one(app, rfile, wfile, session, bodies) is True:
        requests += 1
        session['requests'] = requests
        if requests >= max_requests:
            log.info("%r requests from %r, closing",
                requests, session['client']
            )
            break
    wfile.close()  # Will block till write buffer is flushed


def _handle_one(app, rfile, wfile, session, bodies):
    # Read the next request:
    request = _read_request(rfile, bodies)
    request_method = request['method']
    request_body = request['body']

    # Call the application:
    (status, reason, headers, body) = app(session, request, bodies)

    # Make sure application fully consumed request body:
    if request_body and not request_body.closed:
        raise UnconsumedRequestError(request_body)

    # Make sure HEAD requests are properly handled:
    if request_method == 'HEAD':
        if body is not None:
            raise TypeError(
                'response body must be None when request method is HEAD'
            )
        if 'content-length' in headers:
            if 'transfer-encoding' in headers:
                raise ValueError(
                    'cannot have both content-length and transfer-encoding headers'
                )
        elif headers.get('transfer-encoding') != 'chunked':
            raise ValueError(
                'response to HEAD request must include content-length or transfer-encoding'
            )

    # Set default content-length or transfer-encoding header as needed:
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
    elif body is not None:
        raise TypeError(
            'body: not valid type: {!r}: {!r}'.format(type(body), body)
        )

    # Write response
    _write_response(wfile, status, reason, headers, body)

    # Possibly close the connection:
    if status >= 400 and status not in {404, 409, 412}:
        log.warning('closing connection to %r after %d %r',
            session['client'], status, reason
        )
        return False
    return True


class Server:
    _allowed_options = ('max_connections', 'max_requests', 'timeout', 'bodies')

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
        self.bodies = options.get('bodies', default_bodies)
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
        bodies = self.bodies
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
                    args=(semaphore, max_requests, bodies, sock, address),
                    daemon=True
                )
                thread.start()
            else:
                log.warning('Rejecting connection from %r', address)
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _worker(self, semaphore, max_requests, bodies, sock, address):
        session = {'client': address, 'requests': 0}
        log.info('Connection from %r', address)
        try:
            self._handler(sock, max_requests, session, bodies)
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

    def _handler(self, sock, max_requests, session, bodies):
        if self.on_connect is None or self.on_connect(session, sock) is True:
            _handle_requests(self.app, sock, max_requests, session, bodies)
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

    def _handler(self, sock, max_requests, session, bodies):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        session.update({
            'ssl_cipher': sock.cipher(),
            'ssl_compression': sock.compression(),
        })
        super()._handler(sock, max_requests, session, bodies)

