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
A collection of RGI server applications for common scenarios.
"""


class RouterApp:
    """
    Generic RGI routing middleware.

    For example:

    >>> def foo_app(session, request, api):
    ...     return (200, 'OK', {}, b'foo')
    ... 
    >>> def bar_app(session, request, api):
    ...     return (200, 'OK', {}, b'bar')
    ...
    >>> from degu.applib import RouterApp
    >>> router = RouterApp({'foo': foo_app, 'bar': bar_app})

    """

    __slots__ = ('appmap',)

    def __init__(self, appmap):
        if not isinstance(appmap, dict):
            raise TypeError(
                'appmap: need a {!r}; got a {!r}: {!r}'.format(
                    dict, type(appmap), appmap
                )
            )
        for (key, value) in appmap.items():
            if not (key is None or isinstance(key, str)):
                raise TypeError(
                    'appmap: bad key: need a {!r}; got a {!r}: {!r}'.format(
                        str, type(key), key
                    )
                )
            if not callable(value):
                raise TypeError(
                    'appmap[{!r}]: value not callable: {!r}'.format(key, value)
                )
        self.appmap = appmap

    def __call__(self, session, request, api):
        handler = self.appmap.get(request.shift_path())
        if handler is None:
            return (410, 'Gone', {}, None)
        return handler(session, request, api)

