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
A few simple utility functions useful for most RGI server applications.

The module is heavily inspired by the `wsgiref.util` module in the Python3
standard library:

    https://docs.python.org/3/library/wsgiref.html

FIXME: There are duplicates of more or less equivalent functions in `degu.base`
and `degu.server`.  Once the dust settles in `degu.util`, these duplicates
should be removed.
"""


def shift_path(request):
    """
    Shift path to script in an RGI *request* argument.

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


def relative_uri(request):
    """
    Reconstruct a relative URI from an RGI *request* argument.

    For example, when there is no query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': ''}
    >>> relative_uri(request)
    '/bar/baz'

    And when there is a query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> relative_uri(request)
    '/bar/baz?stuff=junk'

    Note that ``request['script']`` is ignored by this function.
    """
    uri = '/' + '/'.join(request['path'])
    if request['query']:
        return '?'.join((uri, request['query']))
    return uri


def absolute_uri(request):
    """
    Reconstruct an absolute URI from an RGI *request* argument.

    For example, when there is no query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': ''}
    >>> absolute_uri(request)
    '/foo/bar/baz'

    And when there is a query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> absolute_uri(request)
    '/foo/bar/baz?stuff=junk'

    """
    uri = '/' + '/'.join(request['script'] + request['path'])
    if request['query']:
        return '?'.join((uri, request['query']))
    return uri


def output_from_input(connection, input_body):
    if input_body is None:
        return None
    if input_body.chunked:
        return connection['rgi.ChunkedOutput'](input_body)
    else:
        return connection['rgi.Output'](input_body, input_body.content_length)

