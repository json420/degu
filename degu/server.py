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

Consider this simple RGI application:

>>> def demo_app(request):
...     if request['method'] not in ('GET', 'HEAD'):
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'Hello, world!'
...     headers = {'content-length': len(body)}
...     return (200, 'OK', headers, body)
...

For example, a request with the wrong method:

>>> demo_app({'method': 'DELETE', 'path': []})
(405, 'Method Not Allowed', {}, None)

And now a GET request:

>>> demo_app({'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

But note that this application isn't HTTP 1.1 compliant, as it should not return
a response body for a HEAD request:

>>> demo_app({'method': 'HEAD', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

Now consider this example middleware, which checks for just such a faulty
application and overrides its response:

>>> class Middleware:
...     def __init__(self, app):
...         self.app = app
...
...     def __call__(self, request):
...         (status, reason, headers, body) = self.app(request)
...         if request['method'] == 'HEAD' and body is not None:
...             return (500, 'Internal Server Error', {}, None)
...         return (status, reason, headers, body)
...

The middleware will let the response to a GET request pass through unchanged: 

>>> middleware = Middleware(demo_app)
>>> middleware({'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

But it will intercept the faulty response to a HEAD request:

>>> middleware({'method': 'HEAD', 'path': []})
(500, 'Internal Server Error', {}, None)

"""

import socket
import ssl
import logging
import threading

from .base import (
    TYPE_ERROR,
    EmptyLineError,
    build_base_sslctx,
    validate_sslctx,
    makefiles,
    read_lines_iter,
    parse_headers,
    write_chunk,
    Input,
    ChunkedInput,
    Output,
    ChunkedOutput,
    FileOutput,
)


IPv6_LOOPBACK = ('::1', 0, 0, 0)
IPv6_ANY = ('::', 0, 0, 0)
IPv4_LOOPBACK = ('127.0.0.1', 0)
IPv4_ANY = ('0.0.0.0', 0)
ADDRESS_CONSTANTS = (
    IPv6_LOOPBACK,
    IPv6_ANY,
    IPv4_LOOPBACK,
    IPv4_ANY,
)
DEFAULT_ADDRESS = IPv6_LOOPBACK
SERVER_SOCKET_TIMEOUT = 15

log = logging.getLogger()


class UnconsumedRequestError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous request body not consumed: {!r}'.format(body)
        )


def hello_world_app(request):
    body = b'Hello, world!'
    headers = {
        'content-length': len(body),
        'content-type': 'text/plain; charset=utf-8',
    }
    if request['method'] == 'GET':
        return (200, 'OK', headers, body)
    if request['method'] == 'HEAD':
        return (200, 'OK', headers, None)
    return (405, 'Method Not Allowed', {}, None)


def build_server_sslctx(config):
    sslctx = build_base_sslctx()
    sslctx.set_ecdh_curve('prime256v1')  # Enable perfect forward secrecy
    sslctx.options |= ssl.OP_SINGLE_ECDH_USE
    sslctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    sslctx.load_cert_chain(config['cert_file'], config['key_file'])
    if 'ca_file' in config or 'ca_path' in config:
        # Configure for authentication with client certificates:
        sslctx.verify_mode = ssl.CERT_REQUIRED
        sslctx.load_verify_locations(
            cafile=config.get('ca_file'),
            capath=config.get('ca_path'),
        )
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

    Also see `reconstruct_uri()`.
    """
    (method, uri, protocol) = line.split()
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
    if protocol != 'HTTP/1.1':
        raise ValueError('bad HTTP protocol: {!r}'.format(protocol))
    return (method, path_list, query)


def reconstruct_uri(path_list, query):
    """
    Reconstruct a URI from a parsed path_list and query.

    For example, when there is no query:

    >>> reconstruct_uri(['foo', 'bar'], '')
    '/foo/bar'

    And when there is a query:

    >>> reconstruct_uri(['foo', 'bar'], 'stuff=junk')
    '/foo/bar?stuff=junk'

    Also see `parse_request()`.
    """
    path_str = '/' + '/'.join(path_list)
    if query:
        return '?'.join((path_str, query))
    return path_str


def shift_path(request):
    """

    For example:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz']}
    >>> shift_path(request)
    'bar'

    And you can see *request* was updated in place:

    >>> request['script']
    ['foo', 'bar']
    >>> request['path']
    ['baz']

    """
    next = request['path'].pop(0)
    request['script'].append(next)
    return next


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
    elif isinstance(body, (Output, FileOutput)):
        headers.setdefault('content-length', body.content_length)
        if headers['content-length'] != body.content_length:
            raise ValueError(
                "headers['content-length'] != body.content_length: {} != {}".format(headers['content-length'], body.content_length)
            )
    elif isinstance(body, ChunkedOutput):
        headers.setdefault('transfer-encoding', 'chunked') 
    elif body is not None:
        raise TypeError(
            'body: not valid type: {!r}: {!r}'.format(type(body), body)
        )
    if request['method'] == 'HEAD' and body is not None:
        raise TypeError(
            'response body must be None when request method is HEAD'
        )


def iter_response_lines(status, reason, headers):
    yield 'HTTP/1.1 {} {}\r\n'.format(status, reason)
    if headers:
        for key in sorted(headers):
            yield '{}: {}\r\n'.format(key, headers[key])
    yield '\r\n'


class Handler:
    """
    Handles one or more HTTP requests.

    A `Handler` instance is created per TCP connection.
    """

    __slots__ = ('closed', 'app', 'environ', 'sock', 'rfile', 'wfile')

    def __init__(self, app, environ, sock):
        self.closed = False
        self.app = app
        self.environ = environ
        self.sock = sock
        (self.rfile, self.wfile) = makefiles(sock)

    def close(self):
        self.closed = True
        self.rfile.close()
        self.wfile.close()
        self.sock.close()

    def shutdown(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.close()

    def handle(self):
        client = self.environ['client']
        count = 0
        try:
            while not self.closed:
                self.handle_one()
                count += 1
        finally:
            log.info('handled %d requests from %r', count, client)

    def handle_one(self):
        request = self.environ.copy()
        try:
            request.update(self.build_request())
        except EmptyLineError:
            return self.shutdown()
        except ValueError:
            log.exception('client: %r', request['client'])
            return self.write_status_only(400, 'Bad Request')
        if request['method'] not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
            return self.write_status_only(405, 'Method Not Allowed')
        request_body = request['body']
        response = self.app(request)
        if request_body and not request_body.closed:
            raise UnconsumedRequestError(request_body)
        validate_response(request, response)
        self.write_response(response)

    def build_request(self):
        """
        Builds the *environ* fragment unique to a single HTTP request.
        """
        lines = tuple(read_lines_iter(self.rfile))
        (method, path_list, query) = parse_request(lines[0])
        headers = parse_headers(lines[1:])
        # Hack for compatibility with the CouchDB replicator, which annoyingly
        # sends a {'content-length': 0} header with all GET and HEAD requests:
        if method in {'GET', 'HEAD'} and 'content-length' in headers:
            if headers['content-length'] == 0:
                del headers['content-length']
        if 'content-length' in headers:
            body = Input(self.rfile, headers['content-length'])
        elif 'transfer-encoding' in headers:
            body = ChunkedInput(self.rfile)
        else:
            body = None
        if body is not None and method not in {'POST', 'PUT'}:
            raise ValueError(
                'Request body with wrong method: {!r}'.format(method)
            )
        return {
            'method': method,
            'script': [],
            'path': path_list,
            'query': query,
            'headers': headers,
            'body': body,
        }

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
        preamble = ''.join(iter_response_lines(status, reason, headers))
        self.wfile.write(preamble.encode('latin_1'))
        if isinstance(body, (bytes, bytearray)):
            self.wfile.write(body)
        elif isinstance(body, (Output, FileOutput)):
            for buf in body:
                self.wfile.write(buf)
        elif isinstance(body, ChunkedOutput):
            for chunk in body:
                write_chunk(self.wfile, chunk)
        elif body is not None:
            raise TypeError('Bad response body type')
        self.wfile.flush()
        if status >= 400 and status not in {404, 409, 412}:
            self.close()
            log.warning('closed connection to %r after %d %r',
                    self.environ['client'], status, reason)

    def write_status_only(self, status, reason):
        assert isinstance(status, int)
        assert 100 <= status <= 599
        assert isinstance(reason, str)
        assert reason  # reason should be non-empty
        preamble = ''.join(iter_response_lines(status, reason, None))
        self.wfile.write(preamble.encode('latin_1'))
        self.wfile.flush()
        self.close()


class Server:
    scheme = 'http'

    def __init__(self, address, app):
        if not isinstance(address, tuple):
            raise TypeError(
                TYPE_ERROR.format('address', tuple, type(address), address)
            )
        if len(address) == 4:
            family = socket.AF_INET6
        elif len(address) == 2:
            family = socket.AF_INET
        else:
            raise ValueError(
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )
        if not callable(app):
            raise TypeError('app: not callable: {!r}'.format(app))
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(address)
        self.address = self.sock.getsockname()
        self.app = app
        self.sock.listen(5)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.address, self.app
        )

    def build_base_environ(self):
        """
        Builds the base *environ* used throughout instance lifetime.
        """
        return {
            'server': self.address,
            'scheme': self.scheme,
            'rgi.ResponseBody': Output,
            'rgi.FileResponseBody': FileOutput,
            'rgi.ChunkedResponseBody': ChunkedOutput,
        }

    def serve_forever(self):
        base_environ = self.build_base_environ()
        while True:
            (sock, address) = self.sock.accept()
            sock.settimeout(SERVER_SOCKET_TIMEOUT)
            thread = threading.Thread(
                target=self.handle_requests,
                args=(base_environ.copy(), sock, address),
                daemon=True
            )
            thread.start()
            log.info('connection from %r, active_count=%d', address,
                    threading.active_count())

    def handle_requests(self, base_environ, base_sock, address):
        try:
            (environ, sock) = self.build_connection(base_sock, address)
            base_environ.update(environ)
            handler = Handler(self.app, base_environ, sock)
            handler.handle()
        except Exception:
            log.exception('client: %r', address)
        finally:
            try:
                base_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def build_connection(self, sock, address):
        environ = {
            'client': address,
        }
        return (environ, sock)


class SSLServer(Server):
    scheme = 'https'

    def __init__(self, sslctx, address, app):
        validate_sslctx(sslctx)
        super().__init__(address, app)
        self.sslctx = sslctx

    def __repr__(self):
        return '{}({!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.sslctx, self.address, self.app
        )

    def build_connection(self, sock, address):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        environ = {
            'client': address,
            'ssl_cipher': sock.cipher(),
            'ssl_compression': sock.compression(),
        }
        return (environ, sock)


def app_passthrough(app):
    return app


def run_server(queue, bind_address, port, build_func, *build_args):
    try:
        app = build_func(*build_args)
        httpd = Server(app, bind_address, port)
        env = {'port': httpd.port, 'url': httpd.url}
        queue.put(env)
        httpd.serve_forever()
    except Exception as e:
        log.exception('error starting Server:')
        queue.put(e)
        raise e


def start_server(build_func, *build_args, bind_address='127.0.0.1', port=0):
    import multiprocessing
    queue = multiprocessing.Queue()
    if build_func is None:
        build_func = app_passthrough
        assert len(build_args) == 1
    assert callable(build_func)
    args = (queue, bind_address, port, build_func) + build_args
    process = multiprocessing.Process(target=run_server, args=args, daemon=True)
    process.start()
    env = queue.get()
    if isinstance(env, Exception):
        process.terminate()
        process.join()
        raise env
    return (process, env)


def run_sslserver(queue, sslconfig, bind_address, port, build_func, *build_args):
    try:
        sslctx = build_server_sslctx(sslconfig)
        app = build_func(*build_args)
        httpd = SSLServer(sslctx, app, bind_address, port)
        env = {'port': httpd.port, 'url': httpd.url}
        queue.put(env)
        httpd.serve_forever()
    except Exception as e:
        log.exception('error starting SSLServer:')
        queue.put(e)


def start_sslserver(sslconfig, build_func, *build_args, bind_address='127.0.0.1', port=0):
    import multiprocessing
    queue = multiprocessing.Queue()
    if build_func is None:
        build_func = app_passthrough
        assert len(build_args) == 1
    assert callable(build_func)
    args = (queue, sslconfig, bind_address, port, build_func) + build_args
    process = multiprocessing.Process(target=run_sslserver, args=args, daemon=True)
    process.start()
    env = queue.get()
    if isinstance(env, Exception):
        process.terminate()
        process.join()
        raise env
    return (process, env)
