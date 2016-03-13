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
RGI validation middleware.

The `Validator` class is a middleware component for verifying that both server
and application comply with the REST Gateway Interface (RGI) specification.

The aim is to be strict and comprehensive, and to deliver exceedingly clear
error messages when non-conforming behavior is detected.

As such, performance is sacrificed for the sake of clarity and maintainability.
The `Validator` middleware is not intended for everyday production use.
Whenever you use it, expect a substantial performance hit.

`degu.rgi` and its tests should be fully self-contained and should not rely on
any other `degu` functionality.  With time, assuming RGI gains wider adoption,
`degu.rgi` should be split out of Degu and into its own source tree, so that it
can better act as an independent RGI validation tool.
"""

# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

# Allowed values for request.method:
REQUEST_METHODS = ('GET', 'PUT', 'POST', 'DELETE', 'HEAD')

# 'content-length' and 'transfer-encoding' header keys, defined as constants
# here as typing the literals over and over is rather error prone plus is a bit
# too verbose for comfort at times:
LENGTH = 'content-length'
ENCODING = 'transfer-encoding'


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


def _check_type(label, obj, _type):
    if type(obj) is not type:
        raise TypeError(
            TYPE_ERROR.format(label, _type, type(obj), obj) 
        )


def _ensure_attr_is(label, obj, name, expected):
    """
    Raise a ValueError if *obj* attribute *name* is not *expected*.

    For example, when *obj* has the attribute *name*, but said attribute is not
    *expected*:

    >>> import io
    >>> body = io.BytesIO()
    >>> _ensure_attr_is('request.body', body, 'closed', True)
    Traceback (most recent call last):
      ...
    ValueError: request.body.closed must be True; got False

    Or when *obj* has no attribute *name*:

    >>> _ensure_attr_is('request.body', body, 'chunked', False)
    Traceback (most recent call last):
      ...
    ValueError: request.body: 'BytesIO' object has no attribute 'chunked'

    """
    (label, value) = _getattr(label, obj, name)
    if value is not expected:
        raise ValueError(
            '{} must be {!r}; got {!r}'.format(label, expected, value)
        )


def _ensure_attr_equals(label, obj, name, expected):
    (label, value) = _getattr(label, obj, name)
    if value != expected:
        raise ValueError(
            '{} must equal {!r}; got {!r}'.format(label, expected, value)
        )


def _check_dict(label, obj):
    """
    Ensure that *obj* is a `dict` instance and contains only `str` keys.

    For example, when *obj* isn't a `dict`:

    >>> _check_dict('headers', [('foo', 'bar')])
    Traceback (most recent call last):
      ...
    TypeError: headers: need a <class 'dict'>; got a <class 'list'>: [('foo', 'bar')]

    Or when *obj* contains a non-string key:

    >>> _check_dict('headers', {b'foo': 'bar'})
    Traceback (most recent call last):
      ...
    TypeError: headers: keys must be <class 'str'>; got a <class 'bytes'>: b'foo'

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
    """
    Validate *headers* dictionary.

    `_validate_request()` uses this to validate the incoming request headers.

    `_validate_response()` uses this to validate the outgoing response headers.
    """
    _check_dict(label, headers)
    for (key, value) in headers.items():
        if key != key.casefold():
            raise ValueError(
                '{}: non-casefolded header name: {!r}'.format(label, key)
            )
        if not isinstance(value, str) and key != LENGTH:
            raise TypeError(
                '{}[{!r}]: need a {!r}; got a {!r}: {!r}'.format(
                    label, key, str, type(value), value
                )
            )
    if LENGTH in headers:
        if ENCODING in headers:
            raise ValueError(
                '{}: {} and {} in headers'.format(label, LENGTH, ENCODING)
            )
        (l, v) = _get_path(label, headers, LENGTH)
        if not isinstance(v, int):
            raise TypeError(TYPE_ERROR.format(l, int, type(v), v))
        if v < 0:
            raise ValueError('{}: must be >=0; got {!r}'.format(l, v))
    if ENCODING in headers:
        (l, v) = _get_path(label, headers, ENCODING)
        if v != 'chunked':
            raise ValueError("{}: must be 'chunked'; got {!r}".format(l, v))


def _check_address(label, address):
    """
    Validate a socket address.

    `_validate_session()` uses this to validate ``session.address``.

    For example:

    >>> _check_address('session.address', ('::1', 1234, 0, 0))
    >>> _check_address('session.address', ('::1', 1234, 0))
    Traceback (most recent call last):
      ...
    ValueError: session.address: tuple must have 2 or 4 items; got ('::1', 1234, 0)

    """
    if isinstance(address, tuple):
        if len(address) not in (2, 4):
            raise ValueError(
                '{}: tuple must have 2 or 4 items; got {!r}'.format(label, address)
            )
    elif not isinstance(address, (str, bytes)):
        raise TypeError(
            TYPE_ERROR.format(label, (tuple, str, bytes), type(address), address)
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

    >>> _get_path('session', session, 'foo')
    Traceback (most recent call last):
      ...
    ValueError: session['foo'] does not exist

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

    # address:
    (label, value) = _getattr('session', session, 'address')
    _check_address(label, value)

    # requests:
    (label, value) = _getattr('session', session, 'requests')
    if not isinstance(value, int):
        raise TypeError(
            TYPE_ERROR.format(label, int, type(value), value) 
        )
    if value < 0:
        raise ValueError('{} must be >= 0; got {!r}'.format(label, value))

    # store:
    (label, value) = _getattr('session', session, 'store')
    _check_dict(label, value)

    # FIXME: Add tests for session.credentials, session.max_requests


def _reconstruct_uri(request):
    uri = '/' + '/'.join(request.mount + request.path)
    if request.query is None:
        return uri
    return '?'.join([uri, request.query])


def _check_uri_invariant(request):
    uri = _reconstruct_uri(request)
    if uri != request.uri:
        raise ValueError(
            "reconstruct_uri(request) != request.uri: {!r} != {!r}".format(
                uri, request.uri
            )
        )


def _validate_request(bodies, request):
    """
    Validate the *request* argument.
    """

    # request.method:
    (label, value) = _getattr('request', request, 'method')
    if value not in REQUEST_METHODS:
        raise ValueError(
            "{}: value {!r} not in {!r}".format(label, value, REQUEST_METHODS)
        )
    if not (getattr(request, 'body', None) is None or value in {'PUT', 'POST'}):
        raise ValueError(
            "{} cannot be {!r} when request.body is not None".format(label, value)
        )

    # request.uri:
    (label, value) = _getattr('request', request, 'uri')
    if not isinstance(value, str):
        raise TypeError(
            TYPE_ERROR.format(label, str, type(value), value) 
        )

    # request.mount:
    (label, value) = _getattr('request', request, 'mount')
    if not isinstance(value, list):
        raise TypeError(
            TYPE_ERROR.format(label, list, type(value), value) 
        )
    for i in range(len(value)):
        (l, v) = _get_path(label, value, i)
        if not isinstance(v, str):
            raise TypeError(TYPE_ERROR.format(l, str, type(v), v))

    # request.path:
    (label, value) = _getattr('request', request, 'path')
    if not isinstance(value, list):
        raise TypeError(
            TYPE_ERROR.format(label, list, type(value), value) 
        )
    for i in range(len(value)):
        (l, v) = _get_path(label, value, i)
        if not isinstance(v, str):
            raise TypeError(TYPE_ERROR.format(l, str, type(v), v))

    # request.query:
    (label, value) = _getattr('request', request, 'query')
    if not (value is None or isinstance(value, str)):
        raise TypeError(
            TYPE_ERROR.format(label, str, type(value), value) 
        )

    # request.headers:
    (label, value) = _getattr('request', request, 'headers')
    _check_headers(label, value)

    # request.body:
    (label, value) = _getattr('request', request, 'body')
    if value is None:
        # When there is no request body, there should be neither 'content-length'
        # nor 'tranfer-encoding' headers:
        for key in (LENGTH, ENCODING):
            if key in request.headers:
                raise ValueError(
                    "{} is None but {!r} header is included".format(label, key)
                )
        return  # Skip remaining checks when request body is None

    # request.body is not None:
    assert value is not None
    if isinstance(value, bodies.Body):
        _ensure_attr_is(label, value, 'chunked', False)
        if ENCODING in request.headers:
            raise ValueError(
                "{}: bodies.Body with {!r} header".format(label, ENCODING)
            )
        (l1, v1) = _getattr(label, value, 'content_length')
        if LENGTH not in request.headers:
            raise ValueError(
                "{}: bodies.Body, but missing {!r} header".format(label, LENGTH)
            )
        (l2, v2) = _get_path('request.headers', request.headers, LENGTH)
        if v1 != v2:
            raise ValueError(
                '{} != {}: {!r} != {!r}'.format(l1, l2, v1, v2)
            )
    elif isinstance(value, bodies.ChunkedBody):
        _ensure_attr_is(label, value, 'chunked', True)
        if LENGTH in request.headers:
            raise ValueError(
                "{}: bodies.ChunkedBody with {!r} header".format(label, LENGTH)
            )
        if ENCODING not in request.headers:
            raise ValueError(
                "{}: bodies.ChunkedBody, but missing {!r} header".format(label, ENCODING)
            )
        assert request.headers[ENCODING] == 'chunked'
    else:
        body_types = (bodies.Body, bodies.ChunkedBody)
        raise TypeError(
            TYPE_ERROR.format(label, body_types, type(value), value) 
        )

    # Need request.body.state == 0 prior to calling the application:
    _ensure_attr_equals(label, value, 'state', 0)


def _validate_response(bodies, request, response):
    """
    Validate the *response* tuple returned by the application.
    """
    if not isinstance(response, tuple):
        raise TypeError(
            TYPE_ERROR.format('response', tuple, type(response), response)
        )
    if len(response) != 4:
        raise ValueError(
            'len(response) must be 4, got {}'.format(len(response))
        )

    # response[0] (status):
    (label, value) = _get_path('response', response, 0)
    if not isinstance(value, int):
        raise TypeError(
            TYPE_ERROR.format(label, int, type(value), value)
        )
    if not (100 <= value <= 599):
        raise ValueError(
            '{}: need 100 <= status <= 599; got {}'.format(label, value)
        )

    # response[1] (reason):
    (label, value) = _get_path('response', response, 1)
    if not isinstance(value, str):
        raise TypeError(
            TYPE_ERROR.format(label, str, type(value), value)
        )
    if value == '':
        raise ValueError(
            "{}: reason cannot be an empty ''".format(label)
        )

    # response[2] (headers):
    (label, value) = _get_path('response', response, 2)
    _check_headers(label, value)
    if request.method == 'HEAD':
        # response to 'HEAD' request must include either a 'content-length' or a
        # 'transfer-encoding' header (but not both):
        if not {LENGTH, ENCODING}.intersection(value):
            raise ValueError(
                "{}: response to HEAD request must include {!r} or {!r} header".format(
                    label, LENGTH, ENCODING
                )
            )

    # response[3] (body):
    (label, value) = _get_path('response', response, 3)
    if request.method == 'HEAD':
        # response body must be None when request method is 'HEAD':
        if value is not None:
            raise TypeError(
                "{}: must be None when request.method is 'HEAD'; got a {!r}".format(
                    label, type(value)
                )
            )
        return  # Skip remaining tests
    if value is None:
        # When response body is None and request method is not 'HEAD', should
        # include neither 'content-length' nor 'transfer-encoding' headers:
        for key in (LENGTH, ENCODING):
            if key in response[2]:
                raise ValueError(
                    '{}: response body is None, but {!r} header is included'.format(label, key)
                )
        return  # Skip remaning tests
    length_types = (bytes, bytearray, bodies.Body, bodies.BodyIter)
    chunked_types = (bodies.ChunkedBody, bodies.ChunkedBodyIter)
    if isinstance(value, length_types):
        # Cannot include a 'transfer-encoding' header with a length-encoded
        # response body:
        if ENCODING in response[2]:
            raise ValueError(
                '{}: response body is {!r}, but {!r} header is included'.format(
                    label, type(value), ENCODING
                )
            )
        if isinstance(value, (bytes, bytearray)):
            length = len(value)
            _repr = 'len(body)'
        else:
            (l, length) = _getattr(label, value, 'content_length')
            _repr = 'body.content_length'
            _ensure_attr_is(label, value, 'chunked', False)
            _ensure_attr_equals(label, value, 'state', 0)
        if LENGTH in response[2] and response[2][LENGTH] != length:
            raise ValueError(
                '{}: {} is {}, but {!r} is {}'.format(
                    label, _repr, length, LENGTH, response[2][LENGTH]
                )
            )
    elif isinstance(value, chunked_types):
        # Cannot include a 'content-length' header with a chunk-encoded response
        # body:
        if LENGTH in response[2]:
            raise ValueError(
                '{}: response body is {!r}, but {!r} header is included'.format(
                    label, type(value), LENGTH
                )
            )
        _ensure_attr_is(label, value, 'chunked', True)
        _ensure_attr_equals(label, value, 'state', 0)
        name = 'content_length'
        if hasattr(value, name):
            raise ValueError(
                '{}: {!r} must not have a {!r} attribute'.format(
                    label, type(value), name
                )
            )
    else:
        raise TypeError(
            '{}: bad response body type: {!r}'.format(label, type(value))
        )


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

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.app)

    def __call__(self, session, request, bodies):
        _validate_session(session)
        _validate_request(bodies, request)
        _check_uri_invariant(request)
        response = self.app(session, request, bodies)
        _check_uri_invariant(request)
        if request.body is not None and request.body.state != 2:
            # request body was not fully consumed:
            raise ValueError(
                '{} must be 2 after app() was called; got {!r}'.format(
                    "request.body.state", request.body.state
                )
            )
        _validate_response(bodies, request, response)
        return response

    def on_connect(self, session, sock):
        _validate_session(session)
        if session.requests != 0:
            raise ValueError(
                '{} must be 0 when app.on_connect() is called; got {!r}'.format(
                    'session.requests', session.requests
                )
            )
        if self._on_connect is None:
            return True
        allow = self._on_connect(session, sock)
        if not isinstance(allow, bool):
            raise TypeError(
                'app.on_connect() must return a {!r}; got a {!r}: {!r}'.format(
                    bool, type(allow), allow
                )
            )
        return allow

