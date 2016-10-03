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
`degu` - an embedded HTTP server and client library.
"""

__version__ = '0.18.0'


# Common IPv6 and IPv6 *address* constants:
IPv6_LOOPBACK = ('::1', 0, 0, 0)
IPv6_ANY = ('::', 0, 0, 0)
IPv4_LOOPBACK = ('127.0.0.1', 0)
IPv4_ANY = ('0.0.0.0', 0)

# Handy for unit testing through *address* permutations:
ADDRESS_CONSTANTS = (
    IPv6_LOOPBACK,
    IPv6_ANY,
    IPv4_LOOPBACK,
    IPv4_ANY,
)


def _run_server(q, address, build_func, *build_args, **options):
    try:
        from .server import Server
        app = build_func(*build_args)
        httpd = Server(address, app, **options)
        q.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        q.put(e)
        raise e


def _run_sslserver(q, sslconfig, address, build_func, *build_args, **options):
    try:
        from .server import SSLServer
        app = build_func(*build_args)
        httpd = SSLServer(sslconfig, address, app, **options)
        q.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        q.put(e)
        raise e


def _start_server(address, build_func, *build_args, **options):
    import multiprocessing
    q = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_server,
        args=(q, address, build_func) + build_args,
        kwargs=options,
        daemon=True,
    )
    process.start()
    address = q.get()
    if isinstance(address, Exception):
        process.terminate()
        process.join()
        raise address
    return (process, address)


def _start_sslserver(sslconfig, address, build_func, *build_args, **options):
    import multiprocessing
    if not isinstance(sslconfig, dict):
        raise TypeError(
            '{}: need a {!r}; got a {!r}: {!r}'.format(
                'sslconfig', dict, type(sslconfig), sslconfig
            )
        )
    q = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_sslserver,
        args=(q, sslconfig, address, build_func) + build_args,
        kwargs=options,
        daemon=True,
    )
    process.start()
    address = q.get()
    if isinstance(address, Exception):
        process.terminate()
        process.join()
        raise address
    return (process, address)


class _EmbeddedProcess:
    def __del__(self):
        self.terminate()

    def terminate(self):
        if getattr(self, 'process', None) is not None:
            self.process.terminate()
            self.process.join()


class EmbeddedServer(_EmbeddedProcess):
    def __init__(self, address, build_func, *build_args, **options):
        (self.process, self.address) = _start_server(
            address, build_func, *build_args, **options
        )
        self.build_func = build_func
        self.build_args = build_args
        self.options = options


class EmbeddedSSLServer(_EmbeddedProcess):
    def __init__(self, sslconfig, address, build_func, *build_args, **options):
        self.sslconfig = sslconfig
        (self.process, self.address) = _start_sslserver(
            sslconfig, address, build_func, *build_args, **options
        )
        self.build_func = build_func
        self.build_args = build_args
        self.options = options
        self.options = options

