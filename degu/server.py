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
    makefiles,
    read_preamble,
    parse_headers,
    write_body,
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


def validate_response(request, response):
    """
    Deeply validate response from a RGI application.

    This exhaustive validation is expensive, but for now we're focusing on
    stabilizing RGI as a specification and Degu as an implementation.  Soon
    we'll work on wringing more performance out of Degu (and probably wont do
    such deep validation at run-time, just for unit testing).
    """
    (status, reason, headers, body) = response
    if not isinstance(status, int):
        raise TypeError(TYPE_ERROR.format('status', int, type(status), status))
    if not (100 <= status <= 599):
        raise ValueError(
            'status: need 100 <= status <= 599; got {}'.format(status)
        )
    if not isinstance(reason, str):
        raise TypeError(TYPE_ERROR.format('reason', str, type(reason), reason))
    if not reason:
        raise ValueError('reason: cannot be empty')
    if reason.strip() != reason:
        raise ValueError('reason: surrounding whitespace: {!r}'.format(reason))
    if not isinstance(headers, dict):
        raise TypeError(TYPE_ERROR.format('headers', dict, type(headers), headers))
    for (key, value) in headers.items():
        if not isinstance(key, str):
            raise TypeError(
                'bad header name type: {!r}: {!r}'.format(type(key), key)
            )
        if key.casefold() != key:
            raise ValueError('non-casefolded header name: {!r}'.format(key))
        if key == 'content-length':
            if not isinstance(value, int): 
                raise TypeError(
                    TYPE_ERROR.format("headers['content-length']", int, type(value), value)
                )
        elif key == 'transfer-encoding':
            if value != 'chunked':
                raise ValueError(
                    "headers['transfer-encoding']: need 'chunked'; got {!r}".format(value)
                )
        elif not isinstance(value, str):
            raise TypeError(
                TYPE_ERROR.format('headers[{!r}]'.format(key), str, type(value), value)
            )
    if isinstance(body, (bytes, bytearray)):
        headers.setdefault('content-length', len(body))
        if headers['content-length'] != len(body):
            raise ValueError(
                "headers['content-length'] != len(body): {} != {}".format(headers['content-length'], len(body))
            )
    elif isinstance(body, (Body, BodyIter)):
        headers.setdefault('content-length', body.content_length)
        if headers['content-length'] != body.content_length:
            raise ValueError(
                "headers['content-length'] != body.content_length: {} != {}".format(headers['content-length'], body.content_length)
            )
    elif isinstance(body, (ChunkedBody, ChunkedBodyIter)):
        headers.setdefault('transfer-encoding', 'chunked') 
    elif body is not None:
        raise TypeError(
            'body: not valid type: {!r}: {!r}'.format(type(body), body)
        )
    if request['method'] == 'HEAD' and body is not None:
        raise TypeError(
            'response body must be None when request method is HEAD'
        )


def read_request(rfile):
    # Read the entire request preamble:
    (request_line, header_lines) = read_preamble(rfile)

    # Parse the request line:
    (method, path_list, query) = parse_request(request_line)

    # Parse the header lines:
    headers = parse_headers(header_lines)

    # Hack for compatibility with the CouchDB replicator, which annoyingly
    # sends a {'content-length': 0} header with all GET and HEAD requests:
    if method in {'GET', 'HEAD'} and 'content-length' in headers:
        if headers['content-length'] == 0:
            del headers['content-length']

    # Build request body:
    if 'content-length' in headers:
        body = Body(rfile, headers['content-length'])
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
        #'uri': uri,
        'script': [],
        'path': path_list,
        'query': query,
        'headers': headers,
        'body': body,
    }


def write_response(wfile, status, reason, headers, body):
    lines = ['HTTP/1.1 {} {}\r\n'.format(status, reason)]
    lines.extend(
        sorted('{}: {}\r\n'.format(*kv) for kv in headers.items())
    )
    lines.append('\r\n')
    total = wfile.write(''.join(lines).encode('latin_1'))
    if body is None:
        wfile.flush()
        return total
    return total + write_body(wfile, body)


def handle_requests(app, sock, session):
    (rfile, wfile) = makefiles(sock)
    while handle_one(app, rfile, wfile, session) is True:
        session['requests'] += 1
    wfile.close()  # Will block till write buffer is flushed


def handle_one(app, rfile, wfile, session):
    # Read the next request:
    request = read_request(rfile)
    request_method = request['method']
    request_body = request['body']

    # Call the application:
    (status, reason, headers, body) = app(session, request)

    # Make sure application fully consumed request body:
    if request_body and not request_body.closed:
        raise UnconsumedRequestError(request_body)

    # Make sure HEAD requests are properly handled:
    if request_method == 'HEAD':
        if body is not None:
            raise TypeError(
                'response body must be None when request method is HEAD'
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


class Handler:
    """
    Handles one or more HTTP requests.

    A `Handler` instance is created per TCP connection.
    """

    def __init__(self, app, sock, session):
        self.closed = False
        self.app = app
        self.sock = sock
        self.session = session
        (self.rfile, self.wfile) = makefiles(sock)

    def close(self):
        self.closed = True
        self.wfile.close()  # Will block till write buffer is flushed
        self.rfile.close()
        self.sock.close()

    def handle(self):
        while self.closed is False:
            self.handle_one()
            self.session['requests'] += 1

    def handle_one(self):
        request = read_request(self.rfile)
        request_body = request['body']
        response = self.app(self.session, request)
        if request_body and not request_body.closed:
            raise UnconsumedRequestError(request_body)
        validate_response(request, response)
        self.write_response(response)

    def build_request(self):
        """
        Builds the *request* ``dict`` unique to a single HTTP request.
        """
        return read_request(self.rfile)

    def write_response(self, response):
        """
        Write the response to the wfile.

        A somewhat tricky issue is when to close the connection, especially
        because we need to consider not just what's happening in Degu, but also
        what might have happened in an upstream HTTP server (eg, CouchDB) in the
        case of an RGI proxy application.  In general we want to close the
        connection whenever:

            * The TCP stream gets into an inconsistent state, one way or
              another, regardless of how we detect it

            * We receive a malicious or otherwise malformed request, or when
              there is an unhandled server exception; ie, in this scenario we
              should unconditionally close the connection and not think too hard
              about whether the TCP stream might get into an inconsistent state
              as a result of the request

        This has serious security ramifications because we don't want an
        attacker to be able to escalate an attack by first creating an
        inconsistent stream state and then exploiting it.  In a perfect world,
        creating an inconsistent stream state should always result in a closed
        connection (meaning the attacker has to start over with a new
        connection, and new requests).

        From the server perspective, we're most concerned with the stream state
        on the read side (the ``rfile``), although we should never rule out the
        security consequences of the stream state on the write side (the
        ``wfile``), especially considering that Dmedia/Novacut need to interact
        with collaborators who, although presumably trustworthy *people*, should
        not be assumed to be using trustworthy, uncompromised *machines*.
        Actually, we shouldn't assume trustworthy *people* either, but we can be
        polite and just blame the machines :P

        On the read side, we can break things down into three types stream state
        inconsistencies:

            1. The request preamble isn't fully read - Degu offers at least some
               protection against this as it will try to *read* the complete
               preamble (the request line, plus header lines, plus final CRLF)
               before trying to *parse* the preamble

            2. The request body isn't fully read - this is trickier because it
               is the responsibility of the RGI application to read the request
               body; however, `Handler.handle_one()` should raise an
               `UnconsumedRequestError` when it detects that the request body
               was not fully consumed by the RGI application

            3. The rfile is read *past* the end of #1 or #2 - in *theory* this
               should never happen given the current implementation, but that
               also means that in *practice*... this is probably a good place to
               look for vulnerabilities

        Scenarios under which the connection is currently closed:

            1. If a ``ValueError`` is raised when parsing the request, 
               `Handler.handler_one()` will send *only* a "400 Bad Request"
               status line to the client, and will then gracefully close the
               connection (ie, it will try to flush wfile buffer first); this is
               merely a courtesy to the client (and to developers), and it's
               thus certainly up for debate as to whether we should instead
               handle this case the same way as #2 below; although note that in
               this case, only the status line is sent, but no headers, no body
               (especially not a trace in the response body), so this should be
               safe

            2. If any unhandled Exception occurs, `Server.handle_requests()`
               will immediately and forcibly shutdown the connection, without
               first trying to send any response data to the client; note that
               for unhandled exceptions, we send nothing to the client
               whatsoever: no status line, no headers, no trace in the response
               body; this is a good thing (TM)

            3. If the RGI application returns a response status >= 400, and if
               that response status isn't 404, 409, or 412, then the connection
               will be gracefully closed after trying to send the full response

        The reason we handle 404 specially is that it has special, non-error
        meaning in both the Dmedia files app and CouchDB (eg, you often make a
        HEAD or GET request to see if a file or document exists).  Likewise, we
        handle 409 and 412 specially because they have a common, non-error
        meanings in CouchDB.

        Note that RGI applications should return "410 Gone" for any seemingly
        *naughty* request URI, rather than returning "404 Not Found".  Only
        return "404 Not Found" for an otherwise syntactically and semantically
        valid requests for a resource that happens not to exist on the server.

        The motivation for our lenient treatment of 404, 409, and 412 is
        performance.  We're assuming that security critical requests will all
        happen over SSL, where there is a high cost to creating a new
        connection, and where there is motivation to make as many requests as
        possible through a single connection.  In fact, we can generally justify
        this just by the cost of the TCP connection, yet alone the SSL
        connection.  But as always, this is up for debate, so please speak up
        with any concerns.
        """
        (status, reason, headers, body) = response
        write_response(self.wfile, status, reason, headers, body)
        if status >= 400 and status not in {404, 409, 412}:
            self.close()
            log.warning('closing connection to %r after %d %r',
                self.session['client'], status, reason
            )


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
            'rgi.version': (0, 1),
            'rgi.Body': Body,
            'rgi.BodyIter': BodyIter,
            'rgi.ChunkedBody': ChunkedBody,
            'rgi.ChunkedBodyIter': ChunkedBodyIter,
            'scheme': self.scheme,
            'protocol': 'HTTP/1.1',
            'server': self.address,
            'requests': 0,  # Number of fully handled requests
        }

    def serve_forever(self):
        base_session = self.build_base_session()
        while True:
            (sock, address) = self.sock.accept()
            log.info('Connection from %r; active threads: %d',
                address, threading.active_count()
            )
            session = base_session.copy()
            session['client'] = address
            thread = threading.Thread(
                target=self.worker,
                args=(sock, session),
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
        if self.on_connect is None or self.on_connect(sock, session) is True:
            handle_requests(self.app, sock, session)
            #handler = Handler(self.app, sock, session)
            #handler.handle()
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

