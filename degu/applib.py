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


_METHODS = {'GET', 'PUT', 'POST', 'HEAD', 'DELETE'}


class AllowedMethods:
    __slots__ = ('methods',)

    def __init__(self, *methods):
        for m in methods:
            if m not in _METHODS:
                raise ValueError('bad method: {!r}'.format(m))
        self.methods = methods

    def __repr__(self):
        return 'AllowedMethods({})'.format(
            ', '.join(repr(m) for m in self.methods)
        )

    def __call__(self, app):
        return MethodFilter(app, self)

    def isallowed(self, m):
        return m in self.methods


class MethodFilter:
    __slots__ = ('app', 'allowed_methods')

    def __init__(self, app, allowed_methods):
        if not callable(app):
            raise TypeError(
                'app not callable: {!r}'.format(app)
            )
        if type(allowed_methods) is not AllowedMethods:
            raise TypeError(
                'allowed_methods: need a {!r}; got a {!r}: {!r}'.format(
                    AllowedMethods, type(allowed_methods), allowed_methods
                )
            )
        self.app = app
        self.allowed_methods = allowed_methods

    def __call__(self, session, request, api):
        if self.allowed_methods.isallowed(request.method):
            return self.app(session, request, api)
        return (405, 'Method Not Allowed', {}, None)


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


class ProxyApp:
    """
    Generic RGI reverse-proxy application.
    """

    __slots__ = ('client', 'key')

    def __init__(self, client, key='conn'):
        self.client = client
        self.key = key

    def __call__(self, session, request, api):
        conn = session.store.get(self.key)
        if conn is None:
            conn = self.client.connect()
            session.store[self.key] = conn
        return conn.request(
            request.method,
            request.build_proxy_uri(),
            request.headers,
            request.body,
        )

