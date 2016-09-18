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
from random import SystemRandom

from ..misc import mkreq
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
        for m in METHODS:
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

        # All *good* methods allowed:
        good = list(METHODS)
        random.shuffle(good)
        allowed_methods = applib.AllowedMethods(*good)
        inst = applib.MethodFilter(app, allowed_methods)
        for m in METHODS:
            self.assertEqual(inst(None, mkreq(m, '/'), None),
                (200, 'OK', {}, marker)
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

