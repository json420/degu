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
`degu` - an embedded HTTP server and client library.
"""

__version__ = '0.3.0'


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


def _default_build_func(app):
    return app


def _validate_build_func(build_func, *build_args):
    if build_func is None:
        if len(build_args) != 1:
            raise TypeError('build_func is None, but len(build_args) != 1')
        if not callable(build_args[0]):
            raise TypeError(
                'build_func is None, but not callable(build_args[0])'
            )
        build_func = _default_build_func
    if not callable(build_func):
        raise TypeError('build_func: not callable: {!r}'.format(build_func))
    return build_func


def _run_server(queue, address, build_func, *build_args):
    try:
        from .server import Server
        app = build_func(*build_args)
        httpd = Server(address, app)
        queue.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)
        raise e


def _run_sslserver(queue, sslconfig, address, build_func, *build_args):
    try:
        from .server import SSLServer, build_server_sslctx
        sslctx = build_server_sslctx(sslconfig)
        app = build_func(*build_args)
        httpd = SSLServer(sslctx, address, app)
        queue.put(httpd.address)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)
        raise e


def start_server(address, build_func, *build_args):
    import multiprocessing
    build_func = _validate_build_func(build_func, *build_args)
    queue = multiprocessing.Queue()
    args = (queue, address, build_func) + build_args
    process = multiprocessing.Process(target=_run_server, args=args, daemon=True)
    process.start()
    item = queue.get()
    if isinstance(item, Exception):
        process.terminate()
        process.join()
        raise item
    return (process, item)


def start_sslserver(sslconfig, address, build_func, *build_args):
    import multiprocessing
    build_func = _validate_build_func(build_func, *build_args)
    queue = multiprocessing.Queue()
    args = (queue, sslconfig, address, build_func) + build_args
    process = multiprocessing.Process(target=_run_sslserver, args=args, daemon=True)
    process.start()
    item = queue.get()
    if isinstance(item, Exception):
        process.terminate()
        process.join()
        raise item
    return (process, item)

