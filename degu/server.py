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
import ssl

from .base import (
    ParseError,
    makefiles,
    read_line,
    read_headers,
    write_chunk,
    Input,
    ChunkedInput,
)


SOCKET_TIMEOUT = 30


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


def iter_response_lines(status, reason, headers):
    yield 'HTTP/1.1 {:d} {}\r\n'.format(status, reason)
    if headers:
        for key in sorted(headers):
            yield '{}: {}\r\n'.format(key, headers[key])
    yield '\r\n'


class Handler:
    """
    Handles one or more HTTP requests.

    A `Handler` instance is created per TCP connection.
    """

    __slots__ = ('app', 'environ', 'sock', 'rfile', 'wfile')

    def __init__(self, app, environ, sock):
        self.app = app
        self.environ = environ
        self.sock = sock
        (self.rfile, self.wfile) = makefiles(sock)

    def close(self):
        self.rfile.close()
        self.wfile.close()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def handle_one(self):
        try:
            request = self.environ.copy()
            request.update(self.build_request())
            self.validate_request(request)
            response = self.app(request)
            self.validate_response(request, response)
        except Exception as e:
            if isinstance(e, RGIError) and e.status:
                self.send_status_only(e.status)
            else:
                self.send_status_only('500 Internal Server Error')
            raise e
        self.send_response(request, response)

    def build_request(self):
        """
        Builds the *environ* fragment unique to a single HTTP request.
        """
        (method, path_list, query) = parse_request(read_line(self.rfile))
        headers = read_headers(self.rfile)
        if 'content-length' in headers:
            body = Input(self.rfile, headers['content-length'])
        elif 'transfer-encoding' in headers:
            body = ChunkedInput(self.rfile)
        else:
            body = None
        return {
            'method': method,
            'script': [],
            'path': path_list,
            'query': query,
            'headers': headers,
            'body': body,
        }

    def validate_request(self, request):
        if request['body'] is not None:
            if request['method'] not in ('POST', 'PUT'):
                raise RGIError('400 Request Body With Wrong Method')

    def validate_response(self, request, response):
        (status, headers, body) = response
        if request['method'] == 'HEAD' and body is not None:
            raise TypeError(
                'response body must be None when request method is HEAD'
            )

    def send_response(self, request, response):
        (status, headers, body) = response
        preamble = ''.join(iter_response_lines(status, headers))
        self.wfile.write(preamble.encode('latin_1'))
        if isinstance(body, (bytes, bytearray)):
            self.wfile.write(body)
        elif isinstance(body, (ResponseBody, FileResponseBody)):
            for buf in body:
                self.wfile.write(buf)
        elif isinstance(body, ChunkedResponseBody):
            for chunk in body:
                write_chunk(self.wfile, chunk)
        elif body is not None:
            raise TypeError('Bad response body type')
        self.wfile.flush()

    def send_status_only(self, status):
        preamble = ''.join(iter_response_lines(status, None))
        self.wfile.write(preamble.encode('latin_1'))
        self.wfile.flush()


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
            'rgi.version': (0, 1),
            'rgi.multithread': True,
            'rgi.multiprocess': False,
            'rgi.run_once': False,
            'rgi.ResponseBody': Output,
            'rgi.FileResponseBody': FileOutput,
            'rgi.ChunkedResponseBody': ChunkedOutput,
        }

    def build_connection_environ(self, sock, address):
        """
        Builds the *environ* fragment unique to a TCP (and SSL) connection.
        """
        return {
            'client': (address[0], address[1]),
        }

    def serve_forever(self):
        self.environ = self.build_base_environ()
        self.socket.listen(5)
        while True:
            (conn, address) = self.socket.accept()
            conn.settimeout(SOCKET_TIMEOUT)
            thread = threading.Thread(
                target=self.handle_connection,
                args=(conn, address),
            )
            thread.daemon = True
            thread.start()

    def handle_connection(self, conn, address):
        #conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            self.handle_requests(conn, address)
            conn.shutdown(socket.SHUT_RDWR)
        except socket.error:
            log.info('%s\tSocket Timeout/Error', address)
        except Exception:
            log.exception('%s\tUnhandled Exception', address)
        finally:
            conn.close()

    def handle_requests(self, conn, address):
        environ = self.environ.copy()
        environ.update(self.build_connection_environ(conn, address))
        handler = Handler(self.app, environ, conn)
        handler.handle()


class SSLServer(Server):
    scheme = 'https'

    def __init__(self, ssl_ctx, app, bind_address='::1', port=0):
        if not isinstance(ssl_ctx, ssl.SSLContext):
            raise TypeError('ssl_ctx must be an ssl.SSLContext')
        if ssl_ctx.protocol != ssl.PROTOCOL_TLSv1:
            raise ValueError('ssl_ctx.protocol must be ssl.PROTOCOL_TLSv1')
        if not (ssl_ctx.options & ssl.OP_NO_COMPRESSION):
            raise ValueError('ssl_ctx.options must include ssl.OP_NO_COMPRESSION')
        super().__init__(app, bind_address, port)
        self.ssl_ctx = ssl_ctx

    def build_connection_environ(self, conn, address):
        """
        Builds the *environ* fragment unique to a TCP (and SSL) connection.
        """
        environ = {
            'client': (address[0], address[1]),
        }
        return environ
        if self.context is None:
            return environ

        peercert = conn.getpeercert()
        if peercert is None:
            if self.context.verify_mode == ssl.CERT_REQUIRED:
                raise Exception(
                    'peercert is None but verify_mode == CERT_REQUIRED'
                )
            return environ

        if self.context.verify_mode == ssl.CERT_REQUIRED:
            environ['SSL_CLIENT_VERIFY'] = 'SUCCESS'
        subject = dict(peercert['subject'][0])
        if 'commonName' in subject:
            environ['SSL_CLIENT_S_DN_CN'] = subject['commonName']
        issuer = dict(peercert['issuer'][0])
        if 'commonName' in issuer:
            environ['SSL_CLIENT_I_DN_CN'] = issuer['commonName']
        return environ

    def handle_connection(self, conn, address):
        #conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        try:
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            self.handle_requests(conn, address)
            conn.shutdown(socket.SHUT_RDWR)
        except socket.error:
            log.info('%s\tSocket Timeout/Error', address)
        except Exception:
            log.exception('%s\tUnhandled Exception', address)
        finally:
            conn.close()

