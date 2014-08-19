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


def _getattr(label, obj, name):
    """
    `getattr()` with a clearer error message when attribute is missing.
    """
    if not hasattr(obj, name):
        raise ValueError(
            '{}: {!r} object has no attribute {!r}'.format(
                label, type(obj).__name__, name
            )
        )
    label = '{}.{}'.format(label, name)
    return (label, getattr(obj, name))


def _ensure_attr_is(label, obj, name, expected):
    """
    Raise a ValueError if *obj* attribute *name* is not *expected*.

    For example, when *obj* has the attribute *name*, but said attribute is not
    *expected*:

    >>> import io
    >>> body = io.BytesIO()
    >>> _ensure_attr_is("request['body']", body, 'closed', True)
    Traceback (most recent call last):
      ...
    ValueError: request['body'].closed must be True; got False
    
    Or when *obj* has no attribute *name*:

    >>> _ensure_attr_is("request['body']", body, 'chunked', False)
    Traceback (most recent call last):
      ...
    ValueError: request['body']: 'BytesIO' object has no attribute 'chunked'

    """
    (label, value) = _getattr(label, obj, name)
    if value is not expected:
        raise ValueError(
            '{} must be {!r}; got {!r}'.format(label, expected, value)
        )


def _check_dict(label, obj):
    """
    Ensure that *obj* is a `dict` instance and contains only `str` keys.

    For example, when *obj* isn't a `dict`:

    >>> _check_dict('session', [('foo', 'bar')])
    Traceback (most recent call last):
      ...
    TypeError: session: need a <class 'dict'>; got a <class 'list'>: [('foo', 'bar')]

    Or when *obj* contains a non-string key:

    >>> _check_dict('session', {b'foo': 'bar'})
    Traceback (most recent call last):
      ...
    TypeError: session: keys must be <class 'str'>; got a <class 'bytes'>: b'foo'

    """
    if not isinstance(obj, dict):
        raise TypeError(TYPE_ERROR.format(label, dict, type(obj), obj))
    for key in obj:
        if not isinstance(key, str):
            raise TypeError('{}: keys must be {!r}; got a {!r}: {!r}'.format(
                    label, str, type(key), key
                )
            )


def _check_headers(label, headers):
    _check_dict(label, headers)
    for (key, value) in headers.items():
        if key != key.casefold():
            raise ValueError(
                '{}: non-casefolded header name: {!r}'.format(label, key)
            )
        if not isinstance(value, str) and key != 'content-length':
            raise TypeError(
                '{}[{!r}]: need a {!r}; got a {!r}: {!r}'.format(
                    label, key, str, type(value), value
                )
            )
    if 'content-length' in headers:
        if 'transfer-encoding' in headers:
            raise ValueError(
                '{}: content-length and transfer-encoding in headers'.format(label)
            )
        (l, v) = _get_path(label, headers, 'content-length')
        if not isinstance(v, int):
            raise TypeError(TYPE_ERROR.format(l, int, type(v), v))
        if v < 0:
            raise ValueError('{}: must be >=0; got {!r}'.format(l, v))
    if 'transfer-encoding' in headers:
        (l, v) = _get_path(label, headers, 'transfer-encoding')
        if v != 'chunked':
            raise ValueError("{}: must be 'chunked'; got {!r}".format(l, v))


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


def _validate_session(session):
    """
    Validate the *session* argument.
    """
    _check_dict('session', session)

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


def _validate_request(session, request):
    """
    Validate the *request* argument.
    """
    _check_dict('request', request)

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
    if value is None:
        return
    if isinstance(value, session['rgi.Body']):
        _ensure_attr_is(label, value, 'chunked', False)
        if 'transfer-encoding' in request['headers']:
            raise ValueError(
                "{}: 'rgi.Body' with 'transfer-encoding' header".format(label)
            )
        (L1, V1) = _getattr(label, value, 'content_length')
        if 'content-length' not in request['headers']:
            raise ValueError(
                "{}: 'rgi.Body', but missing 'content-length' header".format(label)
            )
        (L2, V2) = _get_path('request', request, 'headers', 'content-length')
        if V1 != V2:
            raise ValueError(
                '{} != {}: {!r} != {!r}'.format(L1, L2, V1, V2)
            )
    elif isinstance(value, session['rgi.ChunkedBody']):
        _ensure_attr_is(label, value, 'chunked', True)
        if 'content-length' in request['headers']:
            raise ValueError(
                "{}: 'rgi.ChunkedBody' with 'content-length' header".format(label)
            )
        if 'transfer-encoding' not in request['headers']:
            raise ValueError(
                "{}: 'rgi.ChunkedBody', but missing 'transfer-encoding' header".format(label)
            )
        assert request['headers']['transfer-encoding'] == 'chunked'
    else:
        body_types = (session['rgi.Body'], session['rgi.ChunkedBody'])
        raise TypeError(
            TYPE_ERROR.format(label, body_types, type(value), value) 
        )
    # body.closed must be False prior to calling the application:
    _ensure_attr_is(label, value, 'closed', False)


def _validate_response(session, request, response):
    pass    


class Validator:
    __slots__ = ('app', '_on_connect')

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
        _validate_request(session, request)
        response = self.app(session, request)
        _validate_response(session, request, response)
        return response

    def on_connect(self, sock, session):
        _validate_session(session)
        if self._on_connect is None:
            return True
        return self._on_connect(sock, session)

