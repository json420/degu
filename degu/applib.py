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

import os
from os import path
from mimetypes import guess_type

try:
    from ._base import (
        Router,
        ProxyApp,
    )
except ImportError:
    from ._basepy import (
        Router,
        ProxyApp,
    )


__all__ = (
    'AllowedMethods',
    'MethodFilter',
    'Router',
    'ProxyApp',
)


_ALLOWED_METHODS = {'GET', 'PUT', 'POST', 'HEAD', 'DELETE'}


class AllowedMethods:
    __slots__ = ('methods',)

    def __init__(self, *methods):
        for m in methods:
            if m not in _ALLOWED_METHODS:
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


class FilesApp:
    __slots__ = ('dir_name', 'dir_fd')

    def __init__(self, dir_name):
        if type(dir_name) is not str:
            raise TypeError(
                'dir_name: need a {!r}; got a {!r}'.format(str, type(dir_name))
            )
        if path.abspath(dir_name) != dir_name:
            raise ValueError(
                'dir_name: not absolute, normalized path: {!r}'.format(dir_name)
            )
        self.dir_name = dir_name
        self.dir_fd = os.open(dir_name, os.O_DIRECTORY)

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.dir_name)

    def __del__(self):
        if hasattr(self, 'dir_fd'):
            os.close(self.dir_fd)
            del self.dir_fd

    def __call__(self, session, request, api):
        if request.method not in {'GET', 'HEAD'}:
            return (405, 'Method Not Allowed', {}, None)
        # FIXME: The Degu server should really disallow '..' and '.' in request
        # path components, although FilesApp should likewise check:
        if '..' in request.path:
            return (400, 'Bad Request', {}, None)
        name = (os.sep.join(request.path) if request.path else 'index.html')
        try:
            if request.method == 'GET':
                fp = open(name, 'rb', buffering=0, opener=self._opener)
                size = os.stat(fp.fileno()).st_size
            else:
                fp = None
                size = os.stat(name, dir_fd=self.dir_fd).st_size
        except FileNotFoundError:
            return (404, 'Not Found', {}, None)
        r = request.headers.get('range')
        if r is None:
            status = 200
            reason = 'OK'
            headers = {'content-length': size}
            if fp is None:
                body = None
            else:
                body = api.Body(fp, size)
        else:
            if r.stop > size:
                return (416, 'Range Not Satisfiable', {}, None)
            length = r.stop - r.start
            status = 206
            reason = 'Partial Content'
            headers = {
                'content-length': length,
                'content-range': api.ContentRange(r.start, r.stop, size),
            }
            if fp is None:
                body = None
            else:
                fp.seek(r.start)
                body = api.Body(fp, length)
        (ct, enc) = guess_type(name)
        if ct is not None:
            headers['content-type'] = ct
        return (status, reason, headers, body)

    def _opener(self, name, flags):
        return os.open(name, flags, dir_fd=self.dir_fd)

