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
RGI validation middleware.

The `Validator` class is a middleware component for verifying that both server
and application comply with the REST Gateway Interface (RGI) specification.

The aim is to be strict and comprehensive, and to deliver clear error messages
when non-conforming behavior is detected.

As such, performance is generally sacrificed for the sake of clarity and
maintainability.  The `Validator` middleware is not intended for everyday
production use.  Whenever you use it, expect a substantial performance hit.

`degu.rgi` and its tests should be fully self-contained and should not rely on
any other `degu` functionality.  With time, assuming RGI gains wider adoption,
`degu.rgi` should be split out of Degu and into its own source tree.
"""


# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

# Allowed values for session['scheme']:
SESSION_SCHEMES = ('http', 'https')

# Allowed values for session['protocol']:
SESSION_PROTOCOLS = ('HTTP/1.1',)

# Allowed values for request['method']:
REQUEST_METHODS = ('GET', 'PUT', 'POST', 'DELETE', 'HEAD')


def _check_str_keys(name, obj):
    """
    Ensure that all keys in *obj* are `str` instances.

    For example:

    >>> _check_str_keys('session', {b'foo': 'bar'})
    Traceback (most recent call last):
      ...
    TypeError: session: keys must be <class 'str'>; got a <class 'bytes'>: b'foo'

    """
    assert isinstance(name, str)
    assert isinstance(obj, dict)
    for key in obj:
        if not isinstance(key, str):
            raise TypeError('{}: keys must be {!r}; got a {!r}: {!r}'.format(
                    name, str, type(key), key
                )
            )


def _get_path(label, value, *path):
    """
    Return a ``(label, value)`` tuple.

    For example, with an empty path:

    >>> session = {'client': ('127.0.0.1', 52521)}
    >>> _get_path('session', session)
    ('session', {'client': ('127.0.0.1', 52521)})

    Or with a single value path:

    >>> _get_path('session', session, 'client')
    ("session['client']", ('127.0.0.1', 52521))

    Or with a path that is 2 deep:

    >>> _get_path('session', session, 'client', 0)
    ("session['client'][0]", '127.0.0.1')
    >>> _get_path('session', session, 'client', 1)
    ("session['client'][1]", 52521)

    Or when first path item is missing:

    >>> _get_path('session', session, 'server')
    Traceback (most recent call last):
      ...
    ValueError: session['server'] does not exist

    Or when the 2nd path item is missing:

    >>> _get_path('session', session, 'client', 2)
    Traceback (most recent call last):
      ...
    ValueError: session['client'][2] does not exist

    Note that this function carries a substantial performance overhead.  But the
    point is to be clear, correct, and maintainable, so that's okay :D
    """
    for key in path:
        assert isinstance(key, (str, int))
        label = '{}[{!r}]'.format(label, key)
        try:
            value = value[key]
        except (KeyError, IndexError):
            raise ValueError(
                '{} does not exist'.format(label)
            )
    return (label, value)


def _check_headers(label, value):
    if not isinstance(value, dict):
        raise TypeError(
            TYPE_ERROR.format(label, dict, type(value), value) 
        )


def _validate_session(session):
    """
    Validate the *session* argument.
    """
    if not isinstance(session, dict):
        raise TypeError(
            TYPE_ERROR.format('session', dict, type(session), session)

        )
    _check_str_keys('session', session)

    # rgi.version:
    (label, value) = _get_path('session', session, 'rgi.version')
    if not isinstance(value, tuple):
        raise TypeError(
            TYPE_ERROR.format(label, tuple, type(value), value) 
        )
    if len(value) != 2:
        raise ValueError(
            'len({}) must be 2; got {}: {!r}'.format(label, len(value), value)
        )
    for i in range(len(value)):
        (label, value) = _get_path('session', session, 'rgi.version', i)
        if not isinstance(value, int):
            raise TypeError(
                TYPE_ERROR.format(label, int, type(value), value) 
            )
        if value < 0:
            raise ValueError('{} must be >= 0; got {!r}'.format(label, value))

    # Make sure Body, BodyIter, ChunkedBody, ChunkedBodyIter are classes:
    keys = (
        'rgi.Body',
        'rgi.BodyIter',
        'rgi.ChunkedBody',
        'rgi.ChunkedBodyIter',
    )
    for key in keys:
        (label, value) = _get_path('session', session, key)
        if not issubclass(value, object):
            raise Exception('Internal error, should not be reached')

    # scheme:
    (label, value) = _get_path('session', session, 'scheme')
    if value not in SESSION_SCHEMES:
        raise ValueError(
            "{}: value {!r} not in {!r}".format(label, value, SESSION_SCHEMES)
        )

    # protocol:
    (label, value) = _get_path('session', session, 'protocol')
    if value not in SESSION_PROTOCOLS:
        raise ValueError(
            "{}: value {!r} not in {!r}".format(label, value, SESSION_PROTOCOLS)
        )

    # server:
    (label, value) = _get_path('session', session, 'server')

    # client:
    (label, value) = _get_path('session', session, 'client')

    # requests:
    (label, value) = _get_path('session', session, 'requests')
    if not isinstance(value, int):
        raise TypeError(
            TYPE_ERROR.format(label, int, type(value), value) 
        )
    if value < 0:
        raise ValueError('{} must be >= 0; got {!r}'.format(label, value))


def _validate_request(request, body_types):
    """
    Validate the *request* argument.
    """
    if not isinstance(request, dict):
        raise TypeError(
            TYPE_ERROR.format('request', dict, type(request), request)

        )
    _check_str_keys('request', request)

    # method:
    (label, value) = _get_path('request', request, 'method')
    if value not in REQUEST_METHODS:
        raise ValueError(
            "{}: value {!r} not in {!r}".format(label, value, REQUEST_METHODS)
        )

    # script:
    (label, value) = _get_path('request', request, 'script')
    if not isinstance(value, list):
        raise TypeError(
            TYPE_ERROR.format(label, list, type(value), value) 
        )
    for i in range(len(value)):
        (label, value) = _get_path('request', request, 'script', i)
        if not isinstance(value, str):
            raise TypeError(
                TYPE_ERROR.format(label, str, type(value), value) 
            )

    # path:
    (label, value) = _get_path('request', request, 'path')
    if not isinstance(value, list):
        raise TypeError(
            TYPE_ERROR.format(label, list, type(value), value) 
        )
    for i in range(len(value)):
        (label, value) = _get_path('request', request, 'path', i)
        if not isinstance(value, str):
            raise TypeError(
                TYPE_ERROR.format(label, str, type(value), value) 
            )

    # query:
    (label, value) = _get_path('request', request, 'query')
    if not isinstance(value, str):
        raise TypeError(
            TYPE_ERROR.format(label, str, type(value), value) 
        )

    # headers:
    (label, value) = _get_path('request', request, 'headers')
    _check_headers(label, value)

    # body:
    (label, value) = _get_path('request', request, 'body')
    if value is not None:
        if not isinstance(value, body_types):
            raise TypeError(
                TYPE_ERROR.format(label, body_types, type(value), value) 
            )
        # body.closed must be False prior to calling the application:
        if value.closed is not False:
            raise ValueError(
                '{}.closed must be False; got {!r}'.format(label, value.closed)
            )


class Validator:
    def __init__(self, app):
        if not callable(app):
            raise TypeError('app: not callable: {!r}'.format(app))
        on_connect = getattr(app, 'on_connect', None)
        if not (on_connect is None or callable(on_connect)):
            raise TypeError(
                'app.on_connect: not callable: {!r}'.format(on_connect)
            )
        self.app = app
        self._on_connect = on_connect

    def __call__(self, session, request):
        _validate_session(session)
        return self.app(session, request)

    def on_connect(self, sock, session):
        _validate_session(session)
        if self._on_connect is None:
            return True
        return self._on_connect(sock, session)

