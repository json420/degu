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

from .base import ParseError


def parse_request(line):
    """
    Parse the request header line.

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
