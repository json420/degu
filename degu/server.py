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

Example RGI application:

>>> def demo_app(request):
...     if request['method'] not in ('GET', 'HEAD'):
...         return (405, 'Method Not Allowed', {}, None)
...     if request['path'] != []:
...         return (404, 'Not Found', {}, None)
...     body = b'Hello, world!'
...     headers = {'content-length': len(body)}
...     return (200, 'OK', headers, body)
...

For example, a request with the wrong method:

>>> demo_app({'method': 'DELETE', 'path': []})
(405, 'Method Not Allowed', {}, None)

A GET request for the wrong path:

>>> demo_app({'method': 'GET', 'path': ['foo']})
(404, 'Not Found', {}, None)

And now a GET request for the correct path:

>>> demo_app({'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

But note that this application isn't correct, as it should not return a response
body for a HEAD request:

>>> demo_app({'method': 'HEAD', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

Which brings us to an example middleware app, which checks for such a faulty
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
    ParseError,
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


SOCKET_TIMEOUT = 20
log = logging.getLogger()


class UnconsumedRequestError(Exception):
    def __init__(self, body):
        self.body = body
        super().__init__(
            'previous request body not consumed: {!r}'.format(body)
        )


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

    Note that the URI "/" is somewhat special case in how it's parsed:

    >>> parse_request('GET / HTTP/1.1')
    ('GET', [], '')

    Also see `reconstruct_uri()`.
    """
    request_parts = line.split(' ')
    if len(request_parts) != 3:
        raise ParseError('Bad Request Line')
    (method, uri, protocol) = request_parts

    # Validate method:
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ParseError('Method Not Allowed')

    # Validate uri, parse into path_list and query:
    if not uri.startswith('/'):
        raise ParseError('Bad Request URI Start')
    if '..' in uri:  # Prevent path-traversal attacks
        raise ParseError('Naughty URI DotDot')
    if '//' in uri:  # The ol double-slash
        raise ParseError('Naughty URI Double Slash')
    if '\\' in uri:  # Prevent backslash ambiguity
        raise ParseError('Naughty URI Backslash')
    uri_parts = uri.split('?')
    if len(uri_parts) == 2:
        (path_str, query) = uri_parts
    elif len(uri_parts) == 1:
        (path_str, query) = (uri_parts[0], '')
    else:
        raise ParseError('Bad Request URI Query')
    # FIXME: Should maybe disallow a trailing / at the end of path_str
    path_list = ([] if path_str == '/' else path_str[1:].split('/'))

    # Validate protocol:
    if protocol != 'HTTP/1.1':
        raise ParseError('505 HTTP Version Not Supported')

    # Return only (method, path_list, query) as protocol isn't interesting:
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

    def handle(self):
        while not self.closed:
            self.handle_one()

    def handle_one(self):
        try:
            request = self.environ.copy()
            request.update(self.build_request())
        except ParseError as e:
            log.exception('client=%r', request['client'])
            return self.send_status_only(e.status, e.reason)
        request_body = request['body']
        response = self.app(request)
        if request_body and not request_body.closed:
            raise UnconsumedRequestError(request_body)
        validate_response(request, response)
        self.send_response(response)

    def build_request(self):
        """
        Builds the *environ* fragment unique to a single HTTP request.
        """
        lines = tuple(read_lines_iter(self.rfile))
        (method, path_list, query) = parse_request(lines[0])
        headers = parse_headers(lines[1:])
        if 'content-length' in headers:
            body = Input(self.rfile, headers['content-length'])
        elif 'transfer-encoding' in headers:
            body = ChunkedInput(self.rfile)
        else:
            body = None
        if body is not None and method not in {'POST', 'PUT'}:
                raise ParseError('Request Body With Wrong Method')
        return {
            'method': method,
            'script': [],
            'path': path_list,
            'query': query,
            'headers': headers,
            'body': body,
        }

    def send_response(self, response):
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

    def send_status_only(self, status, reason):
        assert isinstance(status, int)
        assert 100 <= status <= 599
        assert isinstance(reason, str)
        assert len(reason) > 0
        preamble = ''.join(iter_response_lines(status, reason, None))
        self.wfile.write(preamble.encode('latin_1'))
        self.wfile.flush()
        self.close()


class Server:
    scheme = 'http'

    def __init__(self, app, bind_address='::1', port=0):
        if not callable(app):
            raise TypeError('app not callable: {!r}'.format(app))
        self.app = app
        if bind_address in {'::1', '::'}:
            template = '{}://[::1]:{:d}/'
            self.sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        elif bind_address in {'127.0.0.1', '0.0.0.0'}:
            template = '{}://127.0.0.1:{:d}/'
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            raise ValueError('invalid bind_address: {!r}'.format(bind_address))
        self.sock.bind((bind_address, port))
        self.bind_address = bind_address
        self.port = self.sock.getsockname()[1]
        self.url = template.format(self.scheme, self.port)

    def build_base_environ(self):
        """
        Builds the base *environ* used throughout instance lifetime.
        """
        return {
            'server': (self.bind_address, self.port),
            'scheme': self.scheme,
            'rgi.ResponseBody': Output,
            'rgi.FileResponseBody': FileOutput,
            'rgi.ChunkedResponseBody': ChunkedOutput,
        }

    def serve_forever(self):
        base_environ = self.build_base_environ()
        self.sock.listen(5)
        while True:
            (sock, address) = self.sock.accept()
            sock.settimeout(SOCKET_TIMEOUT)
            thread = threading.Thread(
                target=self.handle_requests,
                args=(base_environ.copy(), sock, address),
            )
            thread.daemon = True
            thread.start()

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
            'client': (address[0], address[1]),
        }
        return (environ, sock)


class SSLServer(Server):
    scheme = 'https'

    # What SSLServer needs to do differently from Server:
    #   1. Wrap a socket.socket in an ssl.SSLSocket
    #   2. Build a different per-connection environ
    # Would be nice to do both in a single method that SSLServer could override:
    #   (conn_environ, sock) = self.build_connection(sock, address)

    def __init__(self, sslctx, app, bind_address='::1', port=0):
        validate_sslctx(sslctx)
        super().__init__(app, bind_address, port)
        self.sslctx = sslctx

    def build_connection(self, sock, address):
        sock = self.sslctx.wrap_socket(sock, server_side=True)
        environ = {
            'client': (address[0], address[1]),
            'ssl_cipher': sock.cipher(),
            'ssl_compression': sock.compression(),
        }
        return (environ, sock)


def run_server(queue, app, bind_address, port):
    try:
        httpd = Server(app, bind_address, port)
        env = {'port': httpd.port, 'url': httpd.url}
        queue.put(env)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)


def start_server(app, bind_address='::1', port=0):
    import multiprocessing
    queue = multiprocessing.Queue()
    args = (queue, app, bind_address, port)
    process = multiprocessing.Process(target=run_server, args=args, daemon=True)
    process.start()
    env = queue.get()
    if isinstance(env, Exception):
        raise env
    return (process, env)


def run_sslserver(queue, sslconfig, app, bind_address, port):
    try:
        sslctx = build_server_sslctx(sslconfig)
        httpd = SSLServer(sslctx, app, bind_address, port)
        env = {'port': httpd.port, 'url': httpd.url}
        queue.put(env)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)


def start_sslserver(sslconfig, app, bind_address='::1', port=0):
    import multiprocessing
    queue = multiprocessing.Queue()
    args = (queue, sslconfig, app, bind_address, port)
    process = multiprocessing.Process(target=run_sslserver, args=args, daemon=True)
    process.start()
    env = queue.get()
    if isinstance(env, Exception):
        raise env
    return (process, env)

