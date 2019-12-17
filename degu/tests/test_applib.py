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
import io
from random import SystemRandom

from .helpers import TempDir, random_start_stop

from ..misc import mkreq
from ..misc import TempServer
from ..client import Client
from ..base import api, EmptyPreambleError
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


class TestFilesApp(TestCase):
    def test_init(self):
        tmp = TempDir()
        app = applib.FilesApp(tmp.dir)
        self.assertEqual(app.dir_name, tmp.dir)
        self.assertIsInstance(app.dir_fd, int)

    def test_repr(self):
        tmp = TempDir()
        app = applib.FilesApp(tmp.dir)
        self.assertEqual(str(app), 'FilesApp({!r})'.format(tmp.dir))

    def test_call(self):
        tmp = TempDir()
        app = applib.FilesApp(tmp.dir)

        # Bad methods:
        for method in ('PUT', 'POST', 'DELETE'):
            r = mkreq(method, '/foo.txt')
            self.assertEqual(app(None, r, api),
                (405, 'Method Not Allowed', {}, None)
            )

        # File doesn't exist:
        for uri in ('/foo.txt', '/', '/index.html'):
            for method in ('GET', 'HEAD'):
                r = mkreq(method, uri)
                self.assertEqual(app(None, r, api),
                    (404, 'Not Found', {}, None)
                )

        # HEAD request:
        data1 = os.urandom(1234)
        tmp.write(data1, 'foo.txt')
        r = mkreq('HEAD', '/foo.txt')
        (status, reason, headers, body) = app(None, r, api)
        self.assertEqual(status, 200)
        self.assertEqual(reason, 'OK')
        self.assertEqual(headers,
            {'content-length': 1234, 'content-type': 'text/plain'}
        )
        self.assertIsNone(body)

        # GET request:
        r = mkreq('GET', '/foo.txt')
        (status, reason, headers, body) = app(None, r, api)
        self.assertEqual(status, 200)
        self.assertEqual(reason, 'OK')
        self.assertEqual(headers,  # Server will add content-length
            {'content-length': 1234, 'content-type': 'text/plain'}
        )
        self.assertIsInstance(body, api.Body)
        self.assertIsInstance(body.rfile, io.FileIO)
        self.assertEqual(body.rfile.tell(), 0)
        self.assertEqual(body.rfile.name, 'foo.txt')
        self.assertEqual(body.read(), data1)

        # '/' should map to '/index.html':
        data2 = os.urandom(2345)
        tmp.write(data2, 'index.html')
        for uri in ('/', '/index.html'):
            r = mkreq('HEAD', uri)
            (status, reason, headers, body) = app(None, r, api)
            self.assertEqual(status, 200)
            self.assertEqual(reason, 'OK')
            self.assertEqual(headers,
                {'content-length': 2345, 'content-type': 'text/html'}
            )
            self.assertIsNone(body)

            r = mkreq('GET', uri)
            (status, reason, headers, body) = app(None, r, api)
            self.assertEqual(status, 200)
            self.assertEqual(reason, 'OK')
            self.assertEqual(headers,  # Server will add content-length
                {'content-length': 2345, 'content-type': 'text/html'}
            )
            self.assertIsInstance(body, api.Body)
            self.assertIsInstance(body.rfile, io.FileIO)
            self.assertEqual(body.rfile.tell(), 0)
            self.assertEqual(body.rfile.name, 'index.html')
            self.assertEqual(body.read(), data2)

            # Range requests:
            total = len(data2)
            for (start, stop) in [
                (0, total + 1),
                (total - 1, total + 1),
                (total, total + 1),
            ]:
                _range = api.Range(start, stop)
                headers = {'range': _range}
                for method in ('GET', 'HEAD'):
                    r = mkreq(method, uri, headers)
                    self.assertEqual(app(None, r, api),
                        (416, 'Range Not Satisfiable', {}, None)
                    )
            for (start, stop) in [
                (0, 1),
                (0, total - 1),
                (1, total),
                (total - 1, total),
                (0, total),
            ]:
                length = stop - start
                _range = api.Range(start, stop)
                r = mkreq('HEAD', uri, {'range': _range})
                (status, reason, headers, body) = app(None, r, api)
                self.assertEqual(status, 206)
                self.assertEqual(reason, 'Partial Content')
                self.assertEqual(headers,
                    {
                        'content-range': api.ContentRange(start, stop, total),
                        'content-length': length,
                        'content-type': 'text/html',
                    }
                )
                self.assertIsNone(body)

                r = mkreq('GET', uri, {'range': _range})
                (status, reason, headers, body) = app(None, r, api)
                self.assertEqual(status, 206)
                self.assertEqual(reason, 'Partial Content')
                self.assertEqual(headers,
                    {
                        'content-range': api.ContentRange(start, stop, total),
                        'content-length': length,
                        'content-type': 'text/html',
                    }
                )
                self.assertIsInstance(body, api.Body)
                self.assertIsInstance(body.rfile, io.FileIO)
                self.assertEqual(body.rfile.tell(), start)
                self.assertEqual(body.rfile.name, 'index.html')
                self.assertEqual(body.read(), data2[start:stop])

    def test_live(self):
        tmp = TempDir()
        app = applib.FilesApp(tmp.dir)
        server = TempServer(('127.0.0.1', 0), app)
        client = Client(server.address)

        uri = '/foo/bar.js'
        for method in ('PUT', 'POST', 'DELETE'):
            conn = client.connect()
            rsp = conn.request(method, uri, {}, None)
            self.assertEqual(rsp.status, 405)
            self.assertEqual(rsp.reason, 'Method Not Allowed')
            self.assertEqual(rsp.headers, {})
            self.assertIsNone(rsp.body)
            # Connection should be closed after a 405 error:
            with self.assertRaises(EmptyPreambleError):
                conn.request(method, uri, {}, None)

        conn = client.connect()
        for method in ('GET', 'HEAD'):
            rsp = conn.request(method, uri, {}, None)
            self.assertEqual(rsp.status, 404)
            self.assertEqual(rsp.reason, 'Not Found')
            self.assertEqual(rsp.headers, {})
            self.assertIsNone(rsp.body)

        total = 9876
        (start, stop) = random_start_stop(total)
        r = api.Range(start, stop)
        data = os.urandom(total)
        tmp.mkdir('foo')
        tmp.write(data, 'foo', 'bar.js')
        for method in ('GET', 'HEAD'):
            rsp = conn.request(method, uri, {}, None)
            self.assertEqual(rsp.status, 200)
            self.assertEqual(rsp.reason, 'OK')
            self.assertEqual(rsp.headers,
                {
                    'content-length': total,
                    'content-type': 'application/javascript',
                }
            )
            if method == 'GET':
                self.assertIsInstance(rsp.body, api.Body)
                self.assertEqual(rsp.body.read(), data)
            else:
                self.assertIsNone(rsp.body)

            rsp = conn.request(method, uri, {'range': r}, None)
            self.assertEqual(rsp.status, 206)
            self.assertEqual(rsp.reason, 'Partial Content')
            self.assertEqual(rsp.headers,
                {
                    'content-length': stop - start,
                    'content-type': 'application/javascript',
                    'content-range': api.ContentRange(start, stop, total),
                }
            )
            if method == 'GET':
                self.assertIsInstance(rsp.body, api.Body)
                self.assertEqual(rsp.body.read(), data[start:stop])
            else:
                self.assertIsNone(rsp.body)

        start = random.randrange(0, total)
        r = api.Range(start, total + 1)
        for method in ('GET', 'HEAD'):
            conn = client.connect()
            rsp = conn.request(method, uri, {'range': r}, None)
            self.assertEqual(rsp.status, 416)
            self.assertEqual(rsp.reason, 'Range Not Satisfiable')
            self.assertEqual(rsp.headers, {})
            self.assertIsNone(rsp.body)
            # Connection should be closed after a 416 error:
            with self.assertRaises(EmptyPreambleError):
                conn.request(method, uri, {}, None)

