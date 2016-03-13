# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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

"""


def shift_path(request):
    """
    Shift path to mount in an RGI *request* argument.

    This function only uses the `mount` and `path` attributes from the
    *request* namedtuple:

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'mount path')
    >>> request = Request(['foo'], ['bar', 'baz'])
    >>> shift_path(request)
    'bar'

    And you can see *request* was updated in place:

    >>> request.mount
    ['foo', 'bar']
    >>> request.path
    ['baz']

    """
    next = request.path.pop(0)
    request.mount.append(next)
    return next


def relative_uri(request):
    """
    Reconstruct a relative URI from an RGI *request* argument.

    This function uses the `path` and `query` attributes from the *request*
    namedtuple:

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'path query')

    For example, when there is no query:

    >>> request = Request(['bar', 'baz'], None)
    >>> relative_uri(request)
    '/bar/baz'

    Or when there is merely an empty query:

    >>> request = Request(['bar', 'baz'], '')
    >>> relative_uri(request)
    '/bar/baz?'

    And when there is a query:

    >>> request = Request(['bar', 'baz'], 'stuff=junk')
    >>> relative_uri(request)
    '/bar/baz?stuff=junk'

    Note that ``request.mount`` is ignored by this function.
    """
    uri = '/' + '/'.join(request.path)
    if request.query is None:
        return uri
    return '?'.join([uri, request.query])


def absolute_uri(request):
    """
    Reconstruct an absolute URI from an RGI *request* argument.

    This function uses the `mount`, `path`, and `query` attributes from the
    *request* namedtuple:

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'mount path query')

    For example, when there is no query:

    >>> request = Request(['foo'], ['bar', 'baz'], None)
    >>> absolute_uri(request)
    '/foo/bar/baz'

    Or when there is merely an empty query:

    >>> request = Request(['foo'], ['bar', 'baz'], '')
    >>> absolute_uri(request)
    '/foo/bar/baz?'

    And when there is a query:

    >>> request = Request(['foo'], ['bar', 'baz'], 'stuff=junk')
    >>> absolute_uri(request)
    '/foo/bar/baz?stuff=junk'

    """
    uri = '/' + '/'.join(request.mount + request.path)
    if request.query is None:
        return uri
    return '?'.join([uri, request.query])

