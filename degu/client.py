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

from .base import (
    ParseError,
    makefiles,
    read_line,
    read_headers,
    write_chunk,
    Input,
    ChunkedInput,
    Output,
    ChunkedOutput,
    FileOutput,
)


Connection = namedtuple('Connection', 'sock rfile wfile')
Response = namedtuple('Response', 'status reason headers body')


def validate_request(method, uri, headers, body):
    if method not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}:
        raise ValueError('invalid method: {!r}'.format(method))
    if not uri.startswith('/'):
        raise ValueError('bad uri: {!r}'.format(uri))
    for key in headers:
        if key.casefold() != key:
            raise ValueError('non-casefolded header name: {!r}'.format(key))
    if isinstance(body, (bytes, bytearray)): 
        headers['content-length'] = len(body)
    elif isinstance(body, (Output, FileOutput)):
        headers['content-length'] = body.content_length
    elif isinstance(body, ChunkedOutput):
        headers['transfer-encoding'] = 'chunked'
    elif body is not None:
        raise TypeError('bad request body type: {!r}'.format(type(body)))
    if {'content-length', 'transfer-encoding'}.issubset(headers):
        raise ValueError('content-length with transfer-encoding')
    if body is None:
        for key in ('content-length', 'transfer-encoding'):
            if key in headers:
                raise ValueError(
                    'cannot include {!r} when body is None'.format(key)
                )
    elif method not in {'PUT', 'POST'}:
        raise ValueError('cannot include body in a {} request'.format(method))


def iter_request_lines(method, uri, headers):
    yield '{} {} HTTP/1.1\r\n'.format(method, uri)
    if headers:
        for key in sorted(headers):
            yield '{}: {}\r\n'.format(key, headers[key])
    yield '\r\n'


def parse_status(line):
    """
    Parse the status line.

    The return value will be a ``(status, reason)`` tuple, and the status will
    be converted into an integer:

    >>> parse_status('HTTP/1.1 404 Not Found')
    (404, 'Not Found')

    """
    line_parts = line.split(' ', 2)
    if len(line_parts) != 3:
        raise ParseError('Bad Status Line')
    (protocol, status_str, reason) = line_parts

    # Validate protocol:
    if protocol != 'HTTP/1.1':
        raise ParseError('HTTP Version Not Supported')

    # Convent status into an int, validate:
    try:
        status = int(status_str)
    except ValueError:
        raise ParseError('Bad Status Code')
    if not (100 <= status <= 599):
        raise ParseError('Invalid Status Code')

    # Validate reason:
    if not reason:
        raise ParseError('Empty Reason')
    if reason.strip() != reason:
        raise ParseError('Extraneous Whitespace In Reason')

    # Return only (status, reason) as protocol isn't interesting:
    return (status, reason)


def read_response(rfile, method):
    (status, reason) = parse_status(read_line(rfile))
    headers = read_headers(rfile)
    if 'content-length' in headers and method != 'HEAD':
        body = Input(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = ChunkedInput(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


    
