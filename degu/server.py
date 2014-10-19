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
from os import path

from .base import (
    TYPE_ERROR,
    Body,
    BodyIter,
    ChunkedBody,
    ChunkedBodyIter,
    default_bodies,
    makefiles,
    read_preamble,
)


SERVER_SOCKET_TIMEOUT = 10
log = logging.getLogger()


class UnconsumedRequestError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous request body not consumed: {!r}'.format(body)
        )


def build_server_sslctx(config):
    """
    Build a strictly configured server-side SSLContext.

    The *config* must be a ``dict`` that always contains at least a
    ``'cert_file'`` and a ``'key_file'``.

    Degu is primarily aimed at P2P services that use client certificates for
    authentication.  In this case, your *config* must also contain a
    ``'ca_file'`` or a ``'ca_dir'`` (or both).  For example:

    >>> config = {
    ...     'cert_file': '/my/server.cert',
    ...     'key_file': '/my/server.key',
    ...     'ca_file': '/my/client.ca',
    ... }
    ...
    >>> sslctx = build_server_sslctx(config)  # doctest: +SKIP
    >>> sslctx.verify_mode is ssl.CERT_REQUIRED  # doctest: +SKIP
    True

    Note that the *verify_mode* was automatically set to ``ssl.CERT_REQUIRED``.

    However, there are scenarios where it makes sense to allow unauthenticated 
    clients to connect to your :class:`SSLServer`.  For example, the Dmedia
    peering protocol requires this.

    But the danger here is that we don't want developers to accidentally
    allow unauthenticated connections by accidentally omitting ``'ca_file'``
    and ``'ca_dir'`` from their *config*.  This was the case in Degu 0.2 and
    earlier.

    This was fixed in Degu 0.3, which requires you to be more explicit by
    including ``'allow_unauthenticated_clients'`` in your *config* (in
    addition to omitting ``'ca_file'`` and ``'ca_dir'``).

    For example:

    >>> config = {
    ...     'cert_file': '/my/server.cert',
    ...     'key_file': '/my/server.key',
    ...     'allow_unauthenticated_clients': True,
    ... }
    ...
    >>> sslctx = build_server_sslctx(config)  # doctest: +SKIP
    >>> sslctx.verify_mode is ssl.CERT_NONE  # doctest: +SKIP
    True

    Note that the *verify_mode* is ``ssl.CERT_NONE``.

    Configuration details and rationale:

        ===========  =================================
        Protocol:    ``PROTOCOL_TLSv1_2``

        Ciphers:     ``'ECDHE-RSA-AES256-GCM-SHA384'``

        ECDH Curve:  ``'secp384r1'``

        Options:     ``OP_NO_COMPRESSION``
                     ``OP_SINGLE_ECDH_USE``
                     ``OP_CIPHER_SERVER_PREFERENCE``
        ===========  =================================


    FIXME: There is a good chance we should not use ECDHE, and if we do, it's
    not overly clear what curve would be the best choice.  In fact, it seems
    current openssl implementations don't offer a conservative, uncontroversial
    option.  See:

        http://safecurves.cr.yp.to/

    To see the available curves supported by openssl, run this::

        openssl ecparam -list_curves

    Also, we should not rule out Diffie–Hellman.  It seems like a more
    conservative choice at this point, and considering the use cases Degu is
    aimed at, it's not a deal-breaker if creating the connection is more
    expensive, as long as we get good performance using the connection.
    """
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

    if not isinstance(config, dict):
        raise TypeError(
            TYPE_ERROR.format('config', dict, type(config), config)
        )

    # For safety and clarity, force all paths to be absolute, normalized paths:
    for key in ('cert_file', 'key_file', 'ca_file', 'ca_path'):
        if key in config:
            value = config[key]
            if value != path.abspath(value):
                raise ValueError(
                    'config[{!r}] is not an absulute, normalized path: {!r}'.format(
                        key, value
                    )
                )

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    sslctx.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
    sslctx.set_ecdh_curve('secp384r1')
    sslctx.options |= ssl.OP_NO_COMPRESSION
    sslctx.options |= ssl.OP_SINGLE_ECDH_USE
    sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    sslctx.load_cert_chain(config['cert_file'], config['key_file'])
    if 'allow_unauthenticated_clients' in config:
        if config['allow_unauthenticated_clients'] is not True:
            raise ValueError(
                'True is only allowed value for allow_unauthenticated_clients'
            )
        if {'ca_file', 'ca_path'}.intersection(config):
            raise ValueError(
                'cannot include ca_file/ca_path allow_unauthenticated_clients'
            )
        return sslctx
    if not {'ca_file', 'ca_path'}.intersection(config):
        raise ValueError(
            'must include ca_file or ca_path (or allow_unauthenticated_clients)'
        )
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.load_verify_locations(
        cafile=config.get('ca_file'),
        capath=config.get('ca_path'),
    )
    return sslctx


def validate_server_sslctx(sslctx):
    # Lazily import `ssl` module to be memory friendly when SSL isn't needed:
    import ssl

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


def parse_request(line):
    """
    Parse the request line.

    The return value will be a ``(method, path_list, query)`` tuple.  For
    example, when there is no query:

    >>> parse_request('GET /foo/bar HTTP/1.1')
    ('GET', ['foo', 'bar'], '')

    And when there is a query:

    >>> parse_request('GET /foo/bar?stuff=junk HTTP/1.1')
    ('GET', ['foo', 'bar'], 'stuff=junk')

    Note that the URI "/" is a special case in how it's parsed:

    >>> parse_request('GET / HTTP/1.1')
    ('GET', [], '')

    """
    (method, uri, protocol) = line.split()
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ValueError('bad HTTP method: {!r}'.format(method))
    if protocol != 'HTTP/1.1':
        raise ValueError('bad HTTP protocol: {!r}'.format(protocol))
    uri_parts = uri.split('?')
    if len(uri_parts) == 2:
        (path_str, query) = uri_parts
    elif len(uri_parts) == 1:
        (path_str, query) = (uri_parts[0], '')
    else:
        raise ValueError('bad request uri: {!r}'.format(uri))
    if path_str[:1] != '/' or '//' in path_str:
        raise ValueError('bad request path: {!r}'.format(path_str))
    path_list = ([] if path_str == '/' else path_str[1:].split('/'))
    return (method, path_list, query)


def read_request(rfile):
    # Read the entire request preamble:
    (request_line, headers) = read_preamble(rfile)

    # Parse the request line:
    (method, uri, protocol) = request_line.split()
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ValueError('bad HTTP method: {!r}'.format(method))
    if protocol != 'HTTP/1.1':
        raise ValueError('bad HTTP protocol: {!r}'.format(protocol))
    uri_parts = uri.split('?')
    if len(uri_parts) == 2:
        (path_str, query) = uri_parts
    elif len(uri_parts) == 1:
        (path_str, query) = (uri_parts[0], '')
    else:
        raise ValueError('bad request uri: {!r}'.format(uri))
    if path_str[:1] != '/' or '//' in path_str:
        raise ValueError('bad request path: {!r}'.format(path_str))
    path_list = ([] if path_str == '/' else path_str[1:].split('/'))

    # Only one dictionary lookup for content-length:
    content_length = headers.get('content-length')

    # Build request body:
    if content_length is not None:
        # Hack for compatibility with the CouchDB replicator, which annoyingly
        # sends a {'content-length': 0} header with all GET and HEAD requests:
        if method in {'GET', 'HEAD'} and content_length == 0:
            del headers['content-length']
        else:
            body = Body(rfile, content_length)
    elif 'transfer-encoding' in headers:
        body = ChunkedBody(rfile)
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
        'path': path_list,
        'query': query,
        'headers': headers,
        'body': body,
    }


def write_response(wfile, status, reason, headers, body):
    # For performance, store these attributes in local variables:
    write = wfile.write
    flush = wfile.flush

    # Write the first line:
    total = write('HTTP/1.1 {} {}\r\n'.format(status, reason).encode())

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


def handle_requests(app, sock, bodies, session):
    (rfile, wfile) = makefiles(sock)
    requests = session['requests']
    assert requests == 0
    while handle_one(app, rfile, wfile, bodies, session) is True:
        requests += 1
        session['requests'] = requests
        if requests >= 5000:
            log.info("%r requests from %r, closing", requests, session['client'])
            break
    wfile.close()  # Will block till write buffer is flushed


def handle_one(app, rfile, wfile, bodies, session):
    # Read the next request:
    request = read_request(rfile)
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
    if isinstance(body, (bytes, bytearray)):
        headers.setdefault('content-length', len(body))
    elif isinstance(body, (Body, BodyIter)):
        headers.setdefault('content-length', body.content_length)
    elif isinstance(body, (ChunkedBody, ChunkedBodyIter)):
        headers.setdefault('transfer-encoding', 'chunked') 
    elif body is not None:
        raise TypeError(
            'body: not valid type: {!r}: {!r}'.format(type(body), body)
        )

    # Write response
    write_response(wfile, status, reason, headers, body)

    # Possibly close the connection:
    if status >= 400 and status not in {404, 409, 412}:
        log.warning('closing connection to %r after %d %r',
            session['client'], status, reason
        )
        return False
    return True


class Server:
    scheme = 'http'

    def __init__(self, address, app):
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
            if path.abspath(address) != address:
                raise ValueError(
                    'address: bad socket filename: {!r}'.format(address)
                )
            family = socket.AF_UNIX
        elif isinstance(address, bytes):
            family = socket.AF_UNIX
        else:
            raise TypeError(
                TYPE_ERROR.format('address', (tuple, str, bytes), type(address), address)
            )
        if not callable(app):
            raise TypeError('app: not callable: {!r}'.format(app))
        on_connect = getattr(app, 'on_connect', None)
        if not (on_connect is None or callable(on_connect)):
            raise TypeError('app.on_connect: not callable: {!r}'.format(app))
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(address)
        self.address = self.sock.getsockname()
        self.app = app
        self.on_connect = on_connect
        self.sock.listen(5)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.address, self.app
        )

    def build_base_session(self):
        """
        Builds the base session used throughout the server lifetime.

        Each new *session* argument starts out as a copy of this.
        """
        return {
            #'rgi.version': (0, 1),
            'scheme': self.scheme,
            'protocol': 'HTTP/1.1',
            'server': self.address,
            'requests': 0,  # Number of fully handled requests
        }

    def serve_forever(self):
        while True:
            (sock, address) = self.sock.accept()
            count = threading.active_count()
            # FIXME: The max connections and timeout value should really both be
            # tunable, but till we decide on the API for this, we're hard-coding
            # a limit of 100 concurrent connections:
            if count > 100:
                log.error('%d connections, rejecting %r', count, address)
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                except OSError:
                    pass
                return
            log.info('Connection from %r; active threads: %d', address, count)
            thread = threading.Thread(
                target=self.worker,
                args=(sock, {'client': address, 'requests': 0}),
                daemon=True
            )
            thread.start()

    def worker(self, sock, session):
        try:
            sock.settimeout(SERVER_SOCKET_TIMEOUT)
            self.handler(sock, session)
        except OSError as e:
            log.info('Handled %d requests from %r: %r', 
                session['requests'], session['client'], e
            )
        except:
            log.exception('Client: %r', session['client'])
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except OSError:
                pass

    def handler(self, sock, session):
        if self.on_connect is None or self.on_connect(session, sock) is True:
            handle_requests(self.app, sock, default_bodies, session)
        else:
            log.warning('rejecting connection: %r', session['client'])


class SSLServer(Server):
    scheme = 'https'

    def __init__(self, sslctx, address, app):
        self.sslctx = validate_server_sslctx(sslctx)
        super().__init__(address, app)

    def __repr__(self):
        return '{}({!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address, self.app
        )

    def handler(self, sock, session):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        session.update({
            'ssl_cipher': sock.cipher(),
            'ssl_compression': sock.compression(),
        })
        super().handler(sock, session)

