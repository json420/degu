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
Unit tests for the `degu.applib` module.
"""

from unittest import TestCase
import os
import sys
from collections import OrderedDict
from random import SystemRandom

from .._basepy import TYPE_ERROR
from ..base import Request
from ..misc import mkreq
from ..sslhelpers import random_id
from ..misc import TempServer
from ..client import Client
from .. import applib


random = SystemRandom()


METHODS = ('GET', 'PUT', 'POST', 'HEAD', 'DELETE')
BAD_METHODS = [
    '',
    'TRACE',
    'OPTIONS',
    'CONNECT',
    'PATCH',
    'GOT',
    'POT',
    'PUSH',
    'HELL',
    'REPEAT',
]
BAD_METHODS.extend(m.lower() for m in METHODS)
BAD_METHODS = tuple(BAD_METHODS)
ALL_METHODS = METHODS + BAD_METHODS


class TestAllowedMethods(TestCase):
    def test_init(self):
        # No methods:
        inst = applib.AllowedMethods()
        self.assertEqual(inst.methods, tuple())

        # 0 to 5 good methods in random order:
        for count in range(6):
            methods = tuple(random.sample(METHODS, count))
            inst = applib.AllowedMethods(*methods)
            self.assertEqual(inst.methods, methods)

        # 0 to 5 good methods plus 1 bad method, all in random order:
        for bad in BAD_METHODS:
            for count in range(6):
                methods = random.sample(METHODS, count)
                methods.append(bad)
                random.shuffle(methods)
                with self.assertRaises(ValueError) as cm:
                    applib.AllowedMethods(*methods)
                self.assertEqual(str(cm.exception),
                    'bad method: {!r}'.format(bad)
                )

    def test_repr(self):
        # Static value sanity check: no methods
        inst = applib.AllowedMethods()
        self.assertEqual(repr(inst), 'AllowedMethods()')

        # Static value sanity check: one or more methods:
        inst = applib.AllowedMethods('HEAD')
        self.assertEqual(repr(inst), "AllowedMethods('HEAD')")
        inst = applib.AllowedMethods('POST', 'DELETE')
        self.assertEqual(repr(inst), "AllowedMethods('POST', 'DELETE')")
        inst = applib.AllowedMethods('PUT', 'HEAD', 'GET')
        self.assertEqual(repr(inst), "AllowedMethods('PUT', 'HEAD', 'GET')")
        inst = applib.AllowedMethods('GET', 'DELETE', 'POST', 'HEAD')
        self.assertEqual(repr(inst),
            "AllowedMethods('GET', 'DELETE', 'POST', 'HEAD')"
        )
        inst = applib.AllowedMethods('GET', 'PUT', 'POST', 'HEAD', 'DELETE')
        self.assertEqual(repr(inst),
            "AllowedMethods('GET', 'PUT', 'POST', 'HEAD', 'DELETE')"
        )

        # 0 to 5 good methods in random order:
        for count in range(6):
            methods = tuple(random.sample(METHODS, count))
            inst = applib.AllowedMethods(*methods)
            self.assertEqual(repr(inst),
                '{}({})'.format(
                    inst.__class__.__name__,
                    ', '.join(repr(m) for m in methods)
                )
            )

    def test_call(self):
        def app(session, request, api):
            return (200, 'OK', {}, None)

        for count in range(6):
            methods = tuple(random.sample(METHODS, count))
            inst = applib.AllowedMethods(*methods)

            # app not callable:
            bad = 'my_app'
            with self.assertRaises(TypeError) as cm:
                inst(bad)
            self.assertEqual(str(cm.exception),
                'app not callable: {!r}'.format(bad)
            )

            # All good:
            method_filter = inst(app)
            self.assertIs(type(method_filter), applib.MethodFilter)
            self.assertIs(method_filter.app, app)
            self.assertIs(method_filter.allowed_methods, inst)

    def test_isallowed(self):
        inst = applib.AllowedMethods('POST')
        self.assertIs(inst.isallowed('POST'), True)
        self.assertIs(inst.isallowed('GET'), False)
        self.assertIs(inst.isallowed('PUT'), False)
        self.assertIs(inst.isallowed('HEAD'), False)
        self.assertIs(inst.isallowed('DELETE'), False)

        inst = applib.AllowedMethods('PUT', 'HEAD')
        self.assertIs(inst.isallowed('HEAD'), True)
        self.assertIs(inst.isallowed('PUT'), True)
        self.assertIs(inst.isallowed('POST'), False)
        self.assertIs(inst.isallowed('GET'), False)
        self.assertIs(inst.isallowed('DELETE'), False)

        for count in range(6):
            methods = tuple(random.sample(METHODS, count))
            inst = applib.AllowedMethods(*methods)
            for m in BAD_METHODS:
                result = (True if m in methods else False)
                self.assertIs(inst.isallowed(m), result)


class TestMethodFilter(TestCase):
    def test_init(self):
        def app(session, request, api):
            return (200, 'OK', {}, None)

        allowed_methods = applib.AllowedMethods('GET', 'HEAD')

        # app not callable:
        bad = 'my_app'
        with self.assertRaises(TypeError) as cm:
            applib.MethodFilter(bad, allowed_methods)
        self.assertEqual(str(cm.exception),
            'app not callable: {!r}'.format(bad)
        )

        # allowed_methods isn't an AllowedMethods instance:
        bad = frozenset(['GET', 'HEAD'])
        with self.assertRaises(TypeError) as cm:
            applib.MethodFilter(app, bad)
        self.assertEqual(str(cm.exception),
            'allowed_methods: need a {!r}; got a {!r}: {!r}'.format(
                applib.AllowedMethods, type(bad), bad
            )
        )

        # All good:
        inst = applib.MethodFilter(app, allowed_methods)
        self.assertIs(type(inst), applib.MethodFilter)
        self.assertIs(inst.app, app)
        self.assertIs(inst.allowed_methods, allowed_methods)

    def test_call(self):
        class App:
            def __init__(self, marker):
                self.__marker = marker

            def __call__(self, session, request, api):
                return (200, 'OK', {}, self.__marker)

        marker = os.urandom(16)
        app = App(marker)

        # No methods allowed:
        allowed_methods = applib.AllowedMethods()
        inst = applib.MethodFilter(app, allowed_methods)
        for m in ALL_METHODS:
            self.assertEqual(inst(None, mkreq(m, '/'), None),
                (405, 'Method Not Allowed', {}, None)
            )

        # One method allowed:
        for allowed in METHODS:
            allowed_methods = applib.AllowedMethods(allowed)
            inst = applib.MethodFilter(app, allowed_methods)
            for m in METHODS:
                request = mkreq(m, '/')
                response = inst(None, request, None)
                if m == allowed:
                    self.assertEqual(response,
                        (200, 'OK', {}, marker)
                    )
                else:
                    self.assertEqual(response,
                        (405, 'Method Not Allowed', {}, None)
                    )
            for m in BAD_METHODS:
                self.assertEqual(inst(None, mkreq(m, '/'), None),
                    (405, 'Method Not Allowed', {}, None)
                )

        # All *good* methods allowed:
        good = list(METHODS)
        random.shuffle(good)
        random.shuffle(good)
        allowed_methods = applib.AllowedMethods(*good)
        inst = applib.MethodFilter(app, allowed_methods)
        for m in METHODS:
            self.assertEqual(inst(None, mkreq(m, '/'), None),
                (200, 'OK', {}, marker)
            )
        for m in BAD_METHODS:
            self.assertEqual(inst(None, mkreq(m, '/'), None),
                (405, 'Method Not Allowed', {}, None)
            )


class TestRouter(TestCase):
    def test_init(self):
        def foo_app(session, request, api):
            return (200, 'OK', {}, b'foo')

        def bar_app(session, request, api):
            return (200, 'OK', {}, b'bar')

        # appmap not a dict instance:
        appmap = [('foo', foo_app), ('bar', bar_app)]
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            'appmap: need a {!r}; got a {!r}: {!r}'.format(dict, list, appmap)
        )

        # appmap has key that is not None or str instance:
        appmap = {'foo': foo_app, 17: bar_app}
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            'appmap key: need a {!r}; got a {!r}: {!r}'.format(
                str, int, 17
            )
        )

        # appmap has value that isn't callable:
        bar_value = random_id()
        appmap = {'foo': foo_app, 'bar': bar_value}
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            "appmap['bar']: value not callable: {!r}".format(bar_value)
        )

        # Empty appmap:
        appmap = {}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap single str key:
        appmap = {'foo': foo_app}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap single key that is None:
        appmap = {None: foo_app}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {None: foo_app})
        
        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap has two keys, both str:
        appmap = {'foo': foo_app, 'bar': bar_app}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # appmap has two keys, one a str and the other None:
        appmap = {'foo': foo_app, None: bar_app}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        appmap = OrderedDict(appmap)
        with self.assertRaises(TypeError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format("appmap", dict, OrderedDict, appmap)
        )

        # Nested appmap:
        key = random_id()
        end = {key: foo_app}
        appmap = end
        for i in range(9):
            appmap = {random_id(): appmap}
        app = applib.Router(appmap)
        self.assertIs(app.appmap, appmap)

        # Nested appmap that exceeds max depth:
        appmap = {random_id(): appmap}
        with self.assertRaises(ValueError) as cm:
            applib.Router(appmap)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )

        # Recursive appmap
        key1 = random_id()
        key2 = random_id()
        appmap1 = {}
        appmap2 = {}
        appmap1[key1] = appmap2
        appmap2[key2] = appmap1
        with self.assertRaises(ValueError) as cm:
            applib.Router(appmap1)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )

    def test_call(self):
        def foo_app(session, request, api):
            return (200, 'OK', {}, b'foo')

        def bar_app(session, request, api):
            return (200, 'OK', {}, b'bar')

        # appmap is empty:
        app = applib.Router({})
        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {})

        # One appmap key, a str:
        app = applib.Router({'foo': foo_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app})

        r = Request('GET', '/bar', {}, None, [], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app})

        # One appmap key, an empty str:
        app = applib.Router({'': foo_app})
        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app})

        r = Request('GET', '/foo/bar', {}, None, ['foo'], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', 'bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app})

        # One appmap key, None:
        app = applib.Router({None: foo_app})
        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {None: foo_app})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {None: foo_app})

        # Two appmap keys, both str:
        app = applib.Router({'foo': foo_app, 'bar': bar_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        r = Request('GET', '/bar', {}, None, [], ['bar'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, ['bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        r = Request('GET', '/baz', {}, None, [], ['baz'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['baz'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, 'bar': bar_app})

        # Two appmap keys, one str one None:
        app = applib.Router({'foo': foo_app, None: bar_app})
        r = Request('GET', '/foo', {}, None, [], ['foo'], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'foo': foo_app, None: bar_app})

        # Two appmap keys, one empty str one None:
        app = applib.Router({'': foo_app, None: bar_app})
        r = Request('GET', '/foo/', {}, None, ['foo'], [''], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, ['foo', ''])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        r = Request('GET', '/', {}, None, [], [], None)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'bar'))
        self.assertEqual(r.mount, [])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        r = Request('GET', '/foo/bar', {}, None, ['foo'], ['bar'], None)
        self.assertEqual(app(None, r, None), (410, 'Gone', {}, None))
        self.assertEqual(r.mount, ['foo', 'bar'])
        self.assertEqual(r.path, [])
        self.assertEqual(app.appmap, {'': foo_app, None: bar_app})

        # Nested appmap:
        keys = [random_id() for i in range(10)]
        appmap = foo_app
        for key in keys:
            appmap = {key: appmap}
        keys.reverse()
        uri = '/' + '/'.join(keys)
        app = applib.Router(appmap)
        r = mkreq('GET', uri)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, keys)
        self.assertEqual(r.path, [])
        for k in r.mount:
            self.assertEqual(sys.getrefcount(k), 3)
        del app
        for key in keys:
            self.assertEqual(sys.getrefcount(appmap), 2)
            self.assertEqual(sys.getrefcount(key), 4)
            appmap = appmap[key]
            self.assertEqual(sys.getrefcount(key), 3)

        # Nested appmap, exceeds ROUTER_MAX_DEPTH:
        keys = [random_id() for i in range(10)]
        appmap = None
        for key in keys:
            if appmap is None:
                last = appmap = {key: foo_app}
            else:
                appmap = {key: appmap}
        keys.reverse()
        uri = '/' + '/'.join(keys)
        app = applib.Router(appmap)
        r = mkreq('GET', uri)
        self.assertEqual(app(None, r, None), (200, 'OK', {}, b'foo'))
        self.assertEqual(r.mount, keys)
        self.assertEqual(r.path, [])
        for k in r.mount:
            self.assertEqual(sys.getrefcount(k), 3)
        keys.append(random_id())
        last[keys[-2]] = {keys[-1]: foo_app}
        uri = '/' + '/'.join(keys)
        r = mkreq('GET', uri)
        with self.assertRaises(ValueError) as cm:
            app(None, r, None)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )
        self.assertEqual(r.mount, keys[:-1])
        self.assertEqual(r.path, keys[-1:])
        del last
        del app
        for key in keys:
            self.assertEqual(sys.getrefcount(appmap), 2)
            self.assertEqual(sys.getrefcount(key), 4)
            appmap = appmap[key]
            self.assertEqual(sys.getrefcount(key), 3)

        # Recursive appmap
        key1 = random_id()
        key2 = random_id()
        uri = '/' + '/'.join([key1, key2] * 5)
        appmap1 = {}
        app = applib.Router(appmap1)
        appmap2 = {}
        appmap1[key1] = appmap2
        appmap2[key2] = appmap1
        r = mkreq('GET', uri)
        with self.assertRaises(ValueError) as cm:
            app(None, r, None)
        self.assertEqual(str(cm.exception),
            'Router: max appmap depth 10 exceeded'
        )


class TestProxyApp(TestCase):
    def test_live(self):
        class Endpoint:
            def __init__(self, marker):
                self.marker = marker

            def __call__(self, session, request, api):
                return (200, 'OK', {}, self.marker)

        marker = os.urandom(16)
        app1 = Endpoint(marker)
        server1 = TempServer(('127.0.0.1', 0), app1)
        client1 = Client(server1.address)

        app2 = applib.ProxyApp(client1)
        server2 = TempServer(('127.0.0.1', 0), app2)
        client2 = Client(server2.address)

        conn = client2.connect()
        r = conn.get('/', {})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'content-length': 16})
        self.assertIs(r.body.chunked, False)
        self.assertEqual(r.body.read(), marker)
        conn.close()

