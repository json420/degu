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
Unit tests for the `degu.server` module`
"""

from unittest import TestCase
import ssl

from .helpers import MockSocket
from degu.base import _TYPE_ERROR
from degu.sslhelpers import random_id
from degu.misc import TempPKI
from degu import base, client


# Good type and value permutations for the CLient *address*:
GOOD_ADDRESSES = (

    # 2-tuple for AF_INET or AF_INET6:
    ('www.wikipedia.org', 80),
    ('208.80.154.224', 80),
    ('2620:0:861:ed1a::1', 80),

    # 4-tuple for AF_INET6:
    ('2620:0:861:ed1a::1', 80, 0, 0),
    ('fe80::e8b:fdff:fe75:402c', 80, 0, 3),  # Link-local

    # str for AF_UNIX:
    '/tmp/my.socket',

    # bytes for AF_UNIX (Linux abstract name):
    b'\x0000022',
)

# Some bad address permutations:
BAD_TUPLE_ADDRESSES = (
    ('::1',),
    ('127.0.0.1',),
    ('::1', 5678, 0),
    ('127.0.0.1', 5678, 0),
    ('::1', 5678, 0, 0, 0),
    ('127.0.0.1', 5678, 0, 0, 0),
)


class TestFunctions(TestCase):
    def test_build_client_sslctx(self):
        # Bad sslconfig type:
        with self.assertRaises(TypeError) as cm:
            client.build_client_sslctx('bad')
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('sslconfig', dict, str, 'bad')
        )
 
        # The remaining test both build_client_sslctx() directly, and the
        # pass-through from _validate_client_sslctx():
        client_sslctx_funcs = (
            client.build_client_sslctx,
            client._validate_client_sslctx,
        )

        # Bad sslconfig['check_hostname'] type:
        for func in client_sslctx_funcs:
            with self.assertRaises(TypeError) as cm:
                func({'check_hostname': 0})
            self.assertEqual(str(cm.exception),
                _TYPE_ERROR.format("sslconfig['check_hostname']", bool, int, 0)
            )

        # sslconfig['key_file'] without sslconfig['cert_file']:
        for func in client_sslctx_funcs:
            with self.assertRaises(ValueError) as cm:
                func({'key_file': '/my/client.key'})
            self.assertEqual(str(cm.exception), 
                "sslconfig['key_file'] provided without sslconfig['cert_file']"
            )

        # Non absulute, non normalized paths:
        good = {
            'ca_file': '/my/sever.ca',
            'ca_path': '/my/sever.ca.dir',
            'cert_file': '/my/client.cert',
            'key_file': '/my/client.key',
        }
        for key in good.keys():
            # Relative path:
            for func in client_sslctx_funcs:
                bad = good.copy()
                value = 'relative/path'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )

            # Non-normalized path with directory traversal:
            for func in client_sslctx_funcs:
                bad = good.copy()
                value = '/my/../secret/path'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )

            # Non-normalized path with trailing slash:
            for func in client_sslctx_funcs:
                bad = good.copy()
                value = '/sorry/very/strict/'
                bad[key] = value
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception),
                    'sslconfig[{!r}] is not an absulute, normalized path: {!r}'.format(key, value)
                )

        # Empty sslconfig, will verify against system-wide CAs, and
        # check_hostname should default to True:
        for func in client_sslctx_funcs:
            sslctx = func({})
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, True)

        # We don't not allow check_hostname to be False when verifying against
        # the system-wide CAs:
        for func in client_sslctx_funcs:
            with self.assertRaises(ValueError) as cm:
                func({'check_hostname': False})
            self.assertEqual(str(cm.exception),
                'check_hostname must be True when using default verify paths'
            )

        # Should work fine when explicitly providing {'check_hostname': True}:
        for func in client_sslctx_funcs:
            sslctx = func({'check_hostname': True})
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, True)

        # Authenticated client sslconfig:
        pki = TempPKI()
        sslconfig = pki.client_sslconfig
        self.assertEqual(set(sslconfig),
            {'ca_file', 'cert_file', 'key_file', 'check_hostname'}
        )
        self.assertIs(sslconfig['check_hostname'], False)
        for func in client_sslctx_funcs:
            sslctx = func(sslconfig)
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, False)

        # check_hostname should default to True:
        del sslconfig['check_hostname']
        for func in client_sslctx_funcs:
            sslctx = func(sslconfig)
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, True)

        # Anonymous client sslconfig:
        sslconfig = pki.anonymous_client_sslconfig
        self.assertEqual(set(sslconfig), {'ca_file', 'check_hostname'})
        self.assertIs(sslconfig['check_hostname'], False)
        for func in client_sslctx_funcs:
            sslctx = func(sslconfig)
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, False)

        # check_hostname should default to True:
        del sslconfig['check_hostname']
        for func in client_sslctx_funcs:
            sslctx = func(sslconfig)
            self.assertIsInstance(sslctx, ssl.SSLContext)
            self.assertEqual(sslctx.protocol, ssl.PROTOCOL_TLSv1_2)
            self.assertEqual(sslctx.verify_mode, ssl.CERT_REQUIRED)
            self.assertIs(sslctx.check_hostname, True)


class TestClient(TestCase):
    def test_init(self):
        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            client.Client(1234)
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        for address in BAD_TUPLE_ADDRESSES:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                client.Client(address)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # Non-absolute/non-normalized AF_UNIX filename:
        with self.assertRaises(ValueError) as cm:
            client.Client('foo')
        self.assertEqual(str(cm.exception),
            "address: bad socket filename: 'foo'"
        )

        # Good address type and value permutations:
        for address in GOOD_ADDRESSES:
            if isinstance(address, tuple):
                host = client._build_host(80, *address)
                headers = (('host', host),)
            else:
                host = None
                headers = None

            inst = client.Client(address)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {})
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `host` option:
            my_host = '.'.join([random_id() for i in range(3)])
            inst = client.Client(address, host=my_host)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'host': my_host})
            self.assertIs(inst.host, my_host)
            self.assertEqual(inst.base_headers, (('host', my_host),))
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding `host` option with `None`:
            inst = client.Client(address, host=None)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'host': None})
            self.assertIsNone(inst.host)
            self.assertIsNone(inst.base_headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `authorization` option:
            my_authorization = random_id()
            inst = client.Client(address, authorization=my_authorization)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'authorization': my_authorization})
            self.assertEqual(inst.host, host)
            self.assertIs(inst.authorization, my_authorization)
            if host is None:
                self.assertEqual(inst.base_headers,
                    (('authorization', my_authorization),)
                )
            else:
                self.assertEqual(inst.base_headers,
                    (('authorization', my_authorization), ('host', host))
                )
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `authorization` option when `host` is
            # also overridden to None:
            inst = client.Client(address,
                authorization=my_authorization,
                host=None,
            )
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options,
                {'authorization': my_authorization, 'host': None}
            )
            self.assertIsNone(inst.host)
            self.assertIs(inst.authorization, my_authorization)
            self.assertEqual(inst.base_headers,
                (('authorization', my_authorization),)
            )
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `timeout` option:
            inst = client.Client(address, timeout=17)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'timeout': 17})
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 17)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `on_connect` option:
            inst = client.Client(address, on_connect=None)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            with self.assertRaises(TypeError) as cm:
                client.Client(address, on_connect='hello')
            self.assertEqual(str(cm.exception),
                "on_connect: not callable: 'hello'"
            )

            def my_on_connect(conn):
                return True
            inst = client.Client(address, on_connect=my_on_connect)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIs(inst.on_connect, my_on_connect)

            # Test overriding all the options together:
            options = {
                'host': my_host,
                'authorization': my_authorization,
                'timeout': 16.9,
                'on_connect': my_on_connect,
            }
            inst = client.Client(address, **options)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, options)
            self.assertIs(inst.host, my_host)
            self.assertIs(inst.authorization, my_authorization)
            self.assertEqual(inst.base_headers,
                (('authorization', my_authorization), ('host', my_host))
            )
            self.assertEqual(inst.timeout, 16.9)
            self.assertIs(inst.on_connect, my_on_connect)

            # Test unsupported options:
            with self.assertRaises(TypeError) as cm:
                client.Client(address, foo=17)
            self.assertEqual(str(cm.exception),
                'unsupported Client() **options: foo'
            )
            with self.assertRaises(TypeError) as cm:
                client.Client(address, foo=17, bar=18)
            self.assertEqual(str(cm.exception),
                'unsupported Client() **options: bar, foo'
            )

    def test_repr(self):
        class Custom(client.Client):
            pass

        for address in GOOD_ADDRESSES:
            inst = client.Client(address)
            self.assertEqual(repr(inst), 'Client({!r})'.format(address))
            inst = Custom(address)
            self.assertEqual(repr(inst), 'Custom({!r})'.format(address))

    def test_set_base_header(self):
        for address in GOOD_ADDRESSES:
            inst = client.Client(address, host=None)
            self.assertIsNone(inst.base_headers)

            key1 = random_id().lower()
            val1_a = random_id()
            self.assertIsNone(inst.set_base_header(key1, val1_a))
            self.assertEqual(inst.base_headers, ((key1, val1_a),))

            key2 = random_id().lower()
            val2 = random_id()
            self.assertIsNone(inst.set_base_header(key2, val2))
            self.assertEqual(inst.base_headers,
                tuple(sorted([(key1, val1_a), (key2, val2)]))
            )

            val1_b = random_id()
            self.assertIsNone(inst.set_base_header(key1, val1_b))
            self.assertEqual(inst.base_headers,
                tuple(sorted([(key1, val1_b), (key2, val2)]))
            )

            self.assertIsNone(inst.set_base_header(key1, None))
            self.assertEqual(inst.base_headers, ((key2, val2),))

            self.assertIsNone(inst.set_base_header(key2, None))
            self.assertIsNone(inst.base_headers)

    def test_connect(self):
        class ClientSubclass(client.Client):
            def __init__(self, sock, host, on_connect=None):
                self.__sock = sock
                self.base_headers = (('host', host),)
                self.on_connect = on_connect

            def create_socket(self):
                return self.__sock

        sock = MockSocket()
        host = random_id().lower()
        inst = ClientSubclass(sock, host)
        self.assertIsNone(inst.on_connect)
        conn = inst.connect()
        self.assertIsInstance(conn, base.Connection)
        self.assertIs(conn.sock, sock)
        self.assertIs(conn.base_headers, inst.base_headers)
        self.assertEqual(sock._calls, [])

        # Should return a new Connection instance each time:
        conn2 = inst.connect()
        self.assertIsNot(conn2, conn)
        self.assertIsInstance(conn2, base.Connection)
        self.assertIs(conn2.sock, sock)
        self.assertIs(conn.base_headers, inst.base_headers)
        self.assertEqual(sock._calls, [])

        # on_connect() returns True:
        def on_connect_true(conn):
            return True
        sock = MockSocket()
        host = random_id().lower()
        inst = ClientSubclass(sock, host, on_connect_true)
        self.assertIs(inst.on_connect, on_connect_true)
        conn = inst.connect()
        self.assertIsInstance(conn, base.Connection)
        self.assertIs(conn.sock, sock)
        self.assertIs(conn.base_headers, inst.base_headers)
        self.assertEqual(sock._calls, [])

        # on_connect() does not return True:
        def on_connect_false(conn):
            return 1
        sock = MockSocket()
        host = random_id().lower()
        inst = ClientSubclass(sock, host, on_connect_false)
        self.assertIs(inst.on_connect, on_connect_false)
        with self.assertRaises(ValueError) as cm:
            conn = inst.connect()
        self.assertEqual(str(cm.exception), 'on_connect() did not return True')


class TestSSLClient(TestCase):
    def test_init(self):
        # sslctx is not an ssl.SSLContext:
        with self.assertRaises(TypeError) as cm:
            client.SSLClient('foo', None)
        self.assertEqual(str(cm.exception), 'sslctx must be an ssl.SSLContext')

        # Bad SSL protocol version:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, None)
        self.assertEqual(str(cm.exception),
            'sslctx.protocol must be ssl.PROTOCOL_TLSv1_2'
        )

        # Note: Python 3.3.4 (and presumably 3.4.0) now disables SSLv2 by
        # default (which is good); Degu enforces this (also good), but because
        # we cannot unset the ssl.OP_NO_SSLv2 bit, we can't unit test to check
        # that Degu enforces this, so for now, we set the bit here so it works
        # with Python 3.3.3 still; see: http://bugs.python.org/issue20207
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        sslctx.options |= ssl.OP_NO_SSLv2

        # not (options & ssl.OP_NO_COMPRESSION)
        sslctx.options |= ssl.OP_NO_SSLv2
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, None)
        self.assertEqual(str(cm.exception),
            'sslctx.options must include ssl.OP_NO_COMPRESSION'
        )

        # verify_mode is not ssl.CERT_REQUIRED:
        sslctx.options |= ssl.OP_NO_COMPRESSION
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, None)
        self.assertEqual(str(cm.exception),
            'sslctx.verify_mode must be ssl.CERT_REQUIRED'
        )

        #############################
        # Good sslctx from here on...
        sslctx.verify_mode = ssl.CERT_REQUIRED

        # Bad address type:
        with self.assertRaises(TypeError) as cm:
            client.SSLClient(sslctx, 1234)
        self.assertEqual(str(cm.exception),
            _TYPE_ERROR.format('address', (tuple, str, bytes), int, 1234)
        )

        # Wrong number of items in address tuple:
        for address in BAD_TUPLE_ADDRESSES:
            self.assertIn(len(address), {1, 3, 5})
            with self.assertRaises(ValueError) as cm:
                client.SSLClient(sslctx, address)
            self.assertEqual(str(cm.exception),
                'address: must have 2 or 4 items; got {!r}'.format(address)
            )

        # Non-absolute/non-normalized AF_UNIX filename:
        with self.assertRaises(ValueError) as cm:
            client.SSLClient(sslctx, 'foo')
        self.assertEqual(str(cm.exception),
            "address: bad socket filename: 'foo'"
        )

        # Good address type and value permutations:
        for address in GOOD_ADDRESSES:
            if isinstance(address, tuple):
                ssl_host = address[0]
                host = client._build_host(443, *address)
                headers = (('host', host),)
            else:
                ssl_host = None
                host = None
                headers = None

            inst = client.SSLClient(sslctx, address)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {})
            self.assertIs(inst.ssl_host, ssl_host)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `host` option:
            my_host = '.'.join([random_id() for i in range(3)])
            inst = client.SSLClient(sslctx, address, host=my_host)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'host': my_host})
            self.assertIs(inst.host, my_host)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `host` option with `None`:
            inst = client.SSLClient(sslctx, address, host=None)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'host': None})
            self.assertIsNone(inst.host)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `authorization` option:
            my_authorization = random_id()
            inst = client.SSLClient(sslctx, address, authorization=my_authorization)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'authorization': my_authorization})
            self.assertEqual(inst.host, host)
            self.assertIs(inst.authorization, my_authorization)
            if host is None:
                self.assertEqual(inst.base_headers,
                    (('authorization', my_authorization),)
                )
            else:
                self.assertEqual(inst.base_headers,
                    (('authorization', my_authorization), ('host', host))
                )
            self.assertEqual(inst.ssl_host, ssl_host)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `authorization` option when `host` is
            # also overridden to None:
            inst = client.SSLClient(sslctx, address,
                authorization=my_authorization,
                host=None,
            )
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options,
                {'authorization': my_authorization, 'host': None}
            )
            self.assertIsNone(inst.host)
            self.assertIs(inst.authorization, my_authorization)
            self.assertEqual(inst.base_headers,
                (('authorization', my_authorization),)
            )
            self.assertEqual(inst.ssl_host, ssl_host)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `ssl_host` options:
            my_ssl_host = '.'.join([random_id(10) for i in range(4)])
            inst = client.SSLClient(sslctx, address, ssl_host=my_ssl_host)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'ssl_host': my_ssl_host})
            self.assertIs(inst.ssl_host, my_ssl_host)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `ssl_host` option with `None`:
            inst = client.SSLClient(sslctx, address, ssl_host=None)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'ssl_host': None})
            self.assertIsNone(inst.ssl_host)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `timeout` option:
            inst = client.SSLClient(sslctx, address, timeout=17)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, {'timeout': 17})
            self.assertIs(inst.ssl_host, ssl_host)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 17)
            self.assertIsNone(inst.on_connect)

            # Test overriding the `on_connect` option:
            with self.assertRaises(TypeError) as cm:
                client.SSLClient(sslctx, address, on_connect='hello')
            self.assertEqual(str(cm.exception),
                "on_connect: not callable: 'hello'"
            )
            def my_on_connect(conn):
                return True
            inst = client.SSLClient(sslctx, address, on_connect=my_on_connect)
            self.assertIs(inst.ssl_host, ssl_host)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIs(inst.on_connect, my_on_connect)

            # Test overriding the `on_connect` option with `None`:
            inst = client.SSLClient(sslctx, address, on_connect=None)
            self.assertIs(inst.ssl_host, ssl_host)
            self.assertEqual(inst.host, host)
            self.assertEqual(inst.base_headers, headers)
            self.assertIsNone(inst.authorization)
            self.assertEqual(inst.timeout, 65)
            self.assertIsNone(inst.on_connect)

            # Test overriding all the options together:
            options = {
                'host': my_host,
                'authorization': my_authorization,
                'ssl_host': my_ssl_host,
                'timeout': 16.9,
                'on_connect': my_on_connect,
            }
            inst = client.SSLClient(sslctx, address, **options)
            self.assertIs(inst.address, address)
            self.assertEqual(inst.options, options)
            self.assertIs(inst.host, my_host)
            self.assertIs(inst.authorization, my_authorization)
            self.assertEqual(inst.base_headers,
                (('authorization', my_authorization), ('host', my_host))
            )
            self.assertIs(inst.ssl_host, my_ssl_host)
            self.assertEqual(inst.timeout, 16.9)
            self.assertIs(inst.on_connect, my_on_connect)

            # Test unsupported options:
            with self.assertRaises(TypeError) as cm:
                client.SSLClient(sslctx, address, foo=17)
            self.assertEqual(str(cm.exception),
                'unsupported SSLClient() **options: foo'
            )
            with self.assertRaises(TypeError) as cm:
                client.SSLClient(sslctx, address, foo=17, bar=18)
            self.assertEqual(str(cm.exception),
                'unsupported SSLClient() **options: bar, foo'
            )

    def test_repr(self):
        class Custom(client.SSLClient):
            pass

        pki = TempPKI()
        sslctx = client.build_client_sslctx(pki.client_sslconfig)
        for address in GOOD_ADDRESSES:
            inst = client.SSLClient(sslctx, address)
            self.assertEqual(repr(inst),
                'SSLClient(<sslctx>, {!r})'.format(address)
            )
            inst = Custom(sslctx, address)
            self.assertEqual(repr(inst),
                'Custom(<sslctx>, {!r})'.format(address)
            )

