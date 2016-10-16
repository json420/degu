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
Pure-Python equivalent of the `degu._base` C extension.

Although `degu._basepy` is automatically imported as a fall-back when the
`degu._base` C extension isn't available, this Python implementation really
isn't meant for production use (mainly because it's much, much slower).

This is a reference implementation whose purpose is only to help enforce the
correctness of the C implementation.
"""

from collections import namedtuple


TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'
TYPE_ERROR2 = '{}: need a {!r}; got a {!r}'

BUF_LEN = 32768  # 32 KiB
SCRATCH_LEN = 32
MAX_LINE_LEN = 4096  # Max length of chunk size line, including CRLF

MAX_CL_LEN = 16  # Max length (in bytes) of a content-length/etc
MAX_LENGTH = 9999999999999999  # Max value for content-length/etc

MAX_HEADER_COUNT = 20

IO_SIZE = 1048576  # 1 MiB
MAX_IO_SIZE = 16777216  # 16 MiB

BODY_READY = 0
BODY_STARTED = 1
BODY_CONSUMED = 2
BODY_ERROR = 3

GET_BIT       = (1 << 0)
PUT_BIT       = (1 << 1)
POST_BIT      = (1 << 2)
HEAD_BIT      = (1 << 3)
DELETE_BIT    = (1 << 4)
PUT_POST_MASK = (PUT_BIT | POST_BIT)

_METHODS = {
    b'GET': ('GET', GET_BIT),
    b'PUT': ('PUT', PUT_BIT),
    b'POST': ('POST', POST_BIT),
    b'HEAD': ('HEAD', HEAD_BIT),
    b'DELETE': ('DELETE', DELETE_BIT),
}
_METHODS_STR = dict((k.decode(), v) for (k, v) in _METHODS.items())

_OK = 'OK'

ROUTER_MAX_DEPTH = 10


APIType = API = namedtuple('API',
    'Body ChunkedBody BodyIter ChunkedBodyIter Range ContentRange'
)
ResponseType = Response = namedtuple('Response', 'status reason headers body')


class EmptyPreambleError(ConnectionError):
    pass


################    BEGIN GENERATED TABLES    ##################################
NAME = frozenset(
    b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
)

DECIMAL = frozenset(b'0123456789')
HEXADECIMAL = frozenset(b'0123456789ABCDEFabcdef')

_LOWER = b'-0123456789abcdefghijklmnopqrstuvwxyz'
_UPPER = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_URI   = b'/?'
_PATH  = b'+.:_~'
_QUERY = b'%&='
_SPACE = b' '
_VALUE = b'"\'()*,;<>[]'

KEY    = frozenset(_LOWER)
VAL    = frozenset(_LOWER + _UPPER + _PATH + _QUERY + _URI + _SPACE + _VALUE)
URI    = frozenset(_LOWER + _UPPER + _PATH + _QUERY + _URI)
PATH   = frozenset(_LOWER + _UPPER + _PATH)
QUERY  = frozenset(_LOWER + _UPPER + _PATH + _QUERY)
REASON = frozenset(_LOWER + _UPPER + _SPACE)
EXTKEY = frozenset(_LOWER + _UPPER)
EXTVAL = frozenset(_LOWER + _UPPER + _PATH + _VALUE)
################    END GENERATED TABLES      ##################################


################################################################################
# Argument type and value checking:

def _check_type(name, obj, _type):
    if type(obj) is not _type:
        raise TypeError(
            TYPE_ERROR.format(name, _type, type(obj), obj)
        )

def _check_type2(name, obj, _type):
    if type(obj) is not _type:
        raise TypeError(
            TYPE_ERROR2.format(name, _type, type(obj))
        )

def _check_tuple(name, obj, size):
    _check_type2(name, obj, tuple)
    if len(obj) != size:
        raise ValueError(
            '{}: need a {}-tuple; got a {}-tuple'.format(name, size, len(obj))
        )
    return obj

def _check_list(name, obj):
    _check_type2(name, obj, list)
    return obj

def _check_bytes(name, obj, max_len=MAX_IO_SIZE):
    assert max_len <= MAX_IO_SIZE
    _check_type2(name, obj, bytes)
    if len(obj) > max_len:
        raise ValueError(
            'need len({}) <= {}; got {}'.format(name, max_len, len(obj))
        )

_OUTGOING_STR = frozenset(chr(i) for i in range(128))

def _check_str(name, obj, minlen=1):
    _check_type(name, obj, str)
    if len(obj) < minlen or not _OUTGOING_STR.issuperset(obj):
        raise ValueError(
            'bad {}: {!r}'.format(name, obj)
        )
    return obj

def _getcallable(objname, obj, name):
    attr = getattr(obj, name)
    if not callable(attr):
        raise TypeError('{}.{}() is not callable'.format(objname, name))
    return attr


################################################################################
# Header parsing:

def _validate_int(name, obj):
    if type(obj) is not int:
        raise TypeError(
            TYPE_ERROR.format(name, int, type(obj), obj)
        )

def _validate_length(name, length):
    _validate_int(name, length)
    if not (0 <= length <= MAX_LENGTH):
        raise ValueError(
            'need 0 <= {} <= {}; got {}'.format(name, MAX_LENGTH, length)
        )
    return length

def _validate_size(name, size, max_size):
    assert 0 <= max_size <= MAX_IO_SIZE
    _validate_int(name, size)
    if not (0 <= size <= max_size):
        raise ValueError(
            'need 0 <= {} <= {}; got {}'.format(name, max_size, size)
        )
    return size

def _validate_exact_size(name, size, expected):
    assert 0 <= expected <= MAX_IO_SIZE
    _validate_int(name, size)
    if size != expected:
        raise ValueError(
            'need {} == {!r}; got {!r}'.format(name, expected, size)
        )
    return size

def _validate_read_size(name, size, remaining):
    if size is None:
        if remaining > MAX_IO_SIZE:
            raise ValueError(
                'would exceed max read size: {} > {}'.format(
                    remaining, MAX_IO_SIZE
                )
            )
        return remaining
    return _validate_size(name, size, MAX_IO_SIZE)


def _recv_into(method, dst):
    max_size = len(dst)
    size = method(dst)
    return _validate_size('received', size, max_size)


def _readinto(method, dst):
    dst = memoryview(dst)
    start = 0
    stop = len(dst)
    while start < stop:
        received = _recv_into(method, dst[start:])
        if received == 0:
            break
        start += received
    if start != stop:
        raise ValueError(
            'expected to read {} bytes, but received {}'.format(stop, start)
        )
    return start

def _readinto_from(robj, dst):
    if type(robj) is SocketWrapper:
        return robj.readinto(dst)
    return _readinto(robj, dst)


def _send(method, src):
    assert len(src) > 0, src
    max_size = len(src)
    size = method(src)
    return _validate_size('sent', size, max_size)


def _write(method, src):
    src = memoryview(src)
    start = 0
    stop = len(src)
    while start < stop:
        sent = _send(method, src[start:])
        if sent == 0:
            break
        start += sent
    if start != stop:
        raise ValueError(
            'expected to write {} bytes, but sent {}'.format(stop, start)
        )
    return start


def _write_to(wobj, src):
    if len(src) == 0:
        return 0
    if type(wobj) is SocketWrapper:
        return wobj._write(src)
    return _write(wobj, src)


def _get_robj(rfile):
    if type(rfile) is SocketWrapper:
        return rfile
    return _getcallable('rfile', rfile, 'readinto')


def _get_readline(rfile):
    if type(rfile) is SocketWrapper:
        return rfile
    return _getcallable('rfile', rfile, 'readline')


def _get_wobj(wfile):
    if type(wfile) is SocketWrapper:
        return wfile
    return _getcallable('wfile', wfile, 'write')


class Range:
    __slots__ = ('_start', '_stop')

    def __init__(self, start, stop):
        start = _validate_length('start', start)
        stop = _validate_length('stop', stop)
        if start >= stop:
            raise ValueError(
                'need start < stop; got {} >= {}'.format(start, stop)
            )
        self._start = start
        self._stop = stop

    @property
    def start(self):
        return self._start

    @property
    def stop(self):
        return self._stop

    def __repr__(self):
        return 'Range({}, {})'.format(self._start, self._stop)

    def __str__(self):
        return 'bytes={}-{}'.format(self._start, self._stop - 1)

    def __eq__(self, other):
        if type(other) is type(self):
            return self._start == other._start and self._stop == other._stop
        if type(other) is str:
            return str(self) == other
        raise TypeError('cannot compare Range() with {!r}'.format(type(other)))

    def __ne__(self, other):
        return not self.__eq__(other)


class ContentRange:
    __slots__ = ('_start', '_stop', '_total')

    def __init__(self, start, stop, total):
        _validate_length('start', start)
        _validate_length('stop', stop)
        _validate_length('total', total)
        if not (start < stop <= total):
            raise ValueError(
                'need start < stop <= total; got ({}, {}, {})'.format(
                    start, stop, total
                )
            )
        self._start = start
        self._stop = stop
        self._total = total

    @property
    def start(self):
        return self._start

    @property
    def stop(self):
        return self._stop

    @property
    def total(self):
        return self._total

    def __repr__(self):
        return 'ContentRange({}, {}, {})'.format(
            self._start, self._stop, self._total
        )

    def __str__(self):
        return 'bytes {}-{}/{}'.format(
            self._start, self._stop - 1, self._total
        )

    def __eq__(self, other):
        if type(other) is type(self):
            return (self._start == other._start
                and self._stop == other._stop
                and self._total == other._total
            )
        if type(other) is str:
            return str(self) == other
        raise TypeError(
            'cannot compare ContentRange() with {!r}'.format(type(other))
        )

    def __ne__(self, other):
        return not self.__eq__(other)


def _parse_key(src):
    if len(src) < 1:
        raise ValueError('header name is empty')
    if len(src) > 32:
        raise ValueError('header name too long: {!r}...'.format(src[:32]))
    if NAME.issuperset(src):
        return src.decode('ascii').lower()
    raise ValueError('bad bytes in header name: {!r}'.format(src))


def parse_header_name(src):
    """
    Used to decode, validate, and case-fold header keys.

    FIXME: drop from public API, replaced by _parse_key().
    """
    return _parse_key(src)


def _parse_val(src):
    if len(src) < 1:
        raise ValueError('header value is empty')
    if VAL.issuperset(src):
        return src.decode('ascii')
    raise ValueError('bad bytes in header value: {!r}'.format(src))


def parse_chunk_size(src):
    L = len(src)
    if (L > 7):
        raise ValueError('chunk_size is too long: {!r}...'.format(src[:7]))
    if not (HEXADECIMAL.issuperset(src) and L >= 1 and (src[0] != 48 or L == 1)):
        raise ValueError('bad chunk_size: {!r}'.format(src))
    size = int(src, 16)
    if size > MAX_IO_SIZE:
        raise ValueError(
            'need chunk_size <= {}; got {}'.format(MAX_IO_SIZE, size)
        )
    assert size >= 0
    return size


def _parse_chunk_extension_key(src):
    if EXTKEY.issuperset(src):
        return src.decode()
    raise ValueError('bad chunk extension key: {!r}'.format(src))


def _parse_chunk_extension_val(src):
    if EXTVAL.issuperset(src):
        return src.decode()
    raise ValueError('bad chunk extension value: {!r}'.format(src))


def parse_chunk_extension(src):
    assert type(src) is bytes
    parts = src.split(b'=', 1)
    if len(parts) == 2 and parts[0] and parts[1]:
        key = _parse_chunk_extension_key(parts[0])
        val = _parse_chunk_extension_val(parts[1])
        return (key, val)
    raise ValueError('bad chunk extension: {!r}'.format(src))


def parse_chunk(src):
    assert type(src) is bytes
    if len(src) < 1:
        raise ValueError('{!r} not found in {!r}...'.format(b'\r\n', b''))
    parts = src.split(b';', 1)
    size = parse_chunk_size(parts[0])
    if len(parts) == 2:
        ext = parse_chunk_extension(parts[1])
    else:
        ext = None
    return (size, ext)


def _parse_decimal(src):
    if len(src) < 1 or len(src) > 16:
        return -1
    if not DECIMAL.issuperset(src):
        return -1
    if len(src) > 1 and src[0:1] == b'0':
        return -1
    return int(src)


def parse_content_length(src):
    assert isinstance(src, bytes)
    if len(src) > 16:
        raise ValueError(
            'content-length too long: {!r}...'.format(src[:16])
        )
    value = _parse_decimal(src)
    if value < 0:
        raise ValueError('bad content-length: {!r}'.format(src))
    return value


def _raise_bad_range(src):
    raise ValueError('bad range: {!r}'.format(src))


def parse_range(src):
    assert isinstance(src, bytes)
    if len(src) > 39:
        raise ValueError('range too long: {!r}...'.format(src[:39]))
    if len(src) < 9 or src[0:6] != b'bytes=':
        _raise_bad_range(src)
    inner = src[6:]
    parts = inner.split(b'-', 1)
    if len(parts) != 2:
        _raise_bad_range(src)
    start = _parse_decimal(parts[0])
    end = _parse_decimal(parts[1])
    if start < 0 or end < start or end >= MAX_LENGTH:
        _raise_bad_range(src)
    return Range(start, end + 1)


def _bad_content_range(src):
    raise ValueError('bad content-range: {!r}'.format(src))

def parse_content_range(src):
    assert isinstance(src, bytes)
    if len(src) > 56:
        raise  ValueError('content-range too long: {!r}...'.format(src[:56]))
    if len(src) < 11 or src[0:6] != b'bytes ':
        _bad_content_range(src)
    inner = src[6:]
    a = inner.split(b'-', 1)
    if len(a) != 2:
        _bad_content_range(src)
    b = a[1].split(b'/', 1)
    if len(b) != 2:
        _bad_content_range(src)
    start = _parse_decimal(a[0])
    end = _parse_decimal(b[0])
    total = _parse_decimal(b[1])
    if start < 0 or end < start or end >= total or total > MAX_LENGTH:
        _bad_content_range(src)
    return ContentRange(start, end + 1, total)


def _parse_header_lines(header_lines, isresponse=False):
    if type(isresponse) is not bool:
        raise TypeError(
            TYPE_ERROR.format('isresponse', bool, type(isresponse), isresponse)
        )
    headers = {}
    flags = 0
    for line in header_lines:
        if len(line) < 4:
            raise ValueError('header line too short: {!r}'.format(line))
        parts = line.split(b': ', 1)
        if len(parts) != 2:
            raise ValueError('bad header line: {!r}'.format(line))
        (key, val) = parts
        key = _parse_key(key)
        if key == 'content-length':
            flags |= 1
            val = parse_content_length(val)
        elif key == 'transfer-encoding':
            flags |= 2
            if val != b'chunked':
                raise ValueError(
                    'bad transfer-encoding: {!r}'.format(val)
                )
            val = 'chunked'
        elif key == 'range':
            flags |= 4
            val = parse_range(val)
        elif key == 'content-range':
            flags |= 8
            val = parse_content_range(val)
        else:
            val = _parse_val(val)
        if headers.setdefault(key, val) is not val:
            raise ValueError(
                'duplicate header: {!r}'.format(line)
            )
    if (flags & 3) == 3:
        raise ValueError(
            'cannot have both content-length and transfer-encoding headers'
        )
    if (flags & 4):
        if (flags & 3):
            raise ValueError(
                'cannot include range header and content-length/transfer-encoding'
            )
        if isresponse:
            raise ValueError(
                "response cannot include a 'range' header"
            )
    if (flags & 8) and not isresponse:
        raise ValueError(
            "request cannot include a 'content-range' header"
        )
    return headers


def parse_headers(src, isresponse=False):
    if src == b'':
        return {}
    return _parse_header_lines(src.split(b'\r\n'), isresponse)



################################################################################
# Request parsing:

def _parse_method(src):
    assert isinstance(src, bytes)
    pair = _METHODS.get(src)
    if pair is None:
        raise ValueError('bad HTTP method: {!r}'.format(src))
    return pair


def parse_method(src):
    if isinstance(src, str):
        src = src.encode()
    return _parse_method(src)


def _parse_path_component(src):
    if PATH.issuperset(src):
        return src.decode('ascii')
    raise ValueError('bad bytes in path component: {!r}'.format(src))


def _parse_path(src):
    if not src:
        raise ValueError('path is empty')
    if src[0:1] != b'/':
        raise ValueError("path[0:1] != b'/': {!r}".format(src))
    if b'//' in src:
        raise ValueError("b'//' in path: {!r}".format(src))
    if src == b'/':
        return []
    return [_parse_path_component(c) for c in src[1:].split(b'/')]


def _parse_query(src):
    if QUERY.issuperset(src):
        return src.decode('ascii')
    raise ValueError('bad bytes in query: {!r}'.format(src))


def _parse_uri(src):
    if not src:
        raise ValueError('uri is empty')
    if not URI.issuperset(src):
        raise ValueError('bad bytes in uri: {!r}'.format(src))
    parts = src.split(b'?', 1)
    path = _parse_path(parts[0])
    if len(parts) == 1:
        return (path, None)
    return (path, _parse_query(parts[1]))


def parse_uri(src):
    (path, query) = _parse_uri(src)
    return (src.decode('ascii'), [], path, query)


def parse_request_line(line):
    if len(line) < 14:
        raise ValueError('request line too short: {!r}'.format(line))
    if line[-9:] != b' HTTP/1.1':
        raise ValueError('bad protocol in request line: {!r}'.format(line[-9:]))
    src = line[:-9]
    items = src.split(b' /', 1)
    if len(items) < 2:
        raise ValueError('bad request line: {!r}'.format(line))
    method = _parse_method(items[0])[0]
    (uri, mount, path, query) = parse_uri(b'/' + items[1])
    return (method, uri, mount, path, query)


def _check_request_body(method, key):
    if method not in {'PUT', 'POST'}:
        raise ValueError('{!r} request with a {!r} header'.format(method, key))


def parse_request(preamble, rfile):
    if preamble == b'':
        raise EmptyPreambleError('request preamble is empty')
    (first_line, *header_lines) = preamble.split(b'\r\n')
    (method, uri, mount, path, query) = parse_request_line(first_line)
    headers = _parse_header_lines(header_lines)
    if 'content-length' in headers:
        _check_request_body(method, 'content-length')
        body = Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        _check_request_body(method, 'transfer-encoding')
        body = ChunkedBody(rfile)
    else:
        body = None
    return Request(method, uri, headers, body, mount, path, query)


_REQUEST_REPR = 'Request(method={!r}, uri={!r}, headers={!r}, body={!r}, \
mount={!r}, path={!r}, query={!r})'


class Request:
    __slots__ = (
        '_method', '_m', '_uri', '_headers', '_body', '_mount', '_path', '_query'
    )

    def __init__(self, method, uri, headers, body, mount, path, query):
        (self._method, self._m) = _check_method(method)
        self._uri = uri
        self._headers = headers
        self._body = body
        self._mount = _check_list('mount', mount)
        self._path = _check_list('path', path)
        self._query = query

    def __repr__(self):
        return _REQUEST_REPR.format(
            self._method,
            self._uri,
            self._headers,
            self._body,
            self._mount,
            self._path,
            self._query,
        )

    @property
    def method(self):
        return self._method

    @property
    def m(self):
        return self._m

    @property
    def uri(self):
        return self._uri

    @property
    def headers(self):
        return self._headers

    @property
    def body(self):
        return self._body

    @property
    def mount(self):
        return self._mount

    @property
    def path(self):
        return self._path

    @property
    def query(self):
        return self._query

    def shift_path(self):
        if not self._path:
            return None
        next = self._path.pop(0)
        self._mount.append(next)
        return next

    def build_proxy_uri(self):
        uri = '/' + '/'.join(self._path)
        if self._query is None:
            return uri
        return '?'.join([uri, self._query])



################################################################################
# Response parsing:

def _parse_status(src):
    if DECIMAL.issuperset(src):
        status = int(src)
        if 100 <= status <= 599:
            return status
    raise ValueError('bad status: {!r}'.format(src))


def _parse_reason(src):
    if REASON.issuperset(src):
        if src == b'OK':
            return _OK
        return src.decode('ascii')
    raise ValueError('bad reason: {!r}'.format(src))


def parse_response_line(src):
    assert isinstance(src, bytes)
    if len(src) < 15:
        raise ValueError('response line too short: {!r}'.format(src))
    if src[0:9] != b'HTTP/1.1 ' or src[12:13] != b' ':
        raise ValueError('bad response line: {!r}'.format(src))
    status = _parse_status(src[9:12])
    reason = _parse_reason(src[13:])
    return (status, reason)


def parse_response(method, preamble, rfile):
    _check_method(method)
    if preamble == b'':
        raise EmptyPreambleError('response preamble is empty')
    (first_line, *header_lines) = preamble.split(b'\r\n')
    (status, reason) = parse_response_line(first_line)
    headers = _parse_header_lines(header_lines, isresponse=True)
    if method == 'HEAD':
        body = None
    elif 'content-length' in headers:
        body = Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = ChunkedBody(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


################################################################################
# Rendering and formatting:

def _check_method(method):
    _check_str('method', method)
    pair = _METHODS_STR.get(method)
    if pair is None:
        raise ValueError('bad method: {!r}'.format(method))
    return pair

def _validate_chunk(chunk):
    _check_tuple('chunk', chunk, 2)
    (ext, data) = chunk
    if ext is not None:
        _check_tuple('chunk[0]', ext, 2)
    _check_bytes('chunk[1]', data, MAX_IO_SIZE)
    return chunk


def _format_chunk(size, ext):
    if ext is None:
        return '{:x}\r\n'.format(size).encode()
    (key, value) = ext
    return '{:x};{}={}\r\n'.format(size, key, value).encode()


def format_chunk(chunk):
    (ext, data) = _validate_chunk(chunk)
    if ext is None:
        return '{:x}\r\n'.format(len(data)).encode()
    (key, value) = ext
    return '{:x};{}={}\r\n'.format(len(data), key, value).encode()


def _write_chunk(wobj, chunk):
    line = format_chunk(chunk)
    total =  _write_to(wobj, line)
    total += _write_to(wobj, chunk[1])
    total += _write_to(wobj, b'\r\n')
    return total


def write_chunk(wfile, chunk):
    return _write_chunk(_get_wobj(wfile), chunk)


class _Output:
    __slots__ = ('dst', 'stop')

    def __init__(self, dst):
        assert isinstance(dst, memoryview)
        self.dst = dst
        self.stop = 0

    def copy_into(self, src):
        assert type(src) is bytes
        assert self.stop <= len(self.dst)
        if self.stop + len(src) > len(self.dst):
            raise ValueError(
                'output size exceeds {}'.format(len(self.dst))
            )
        start = self.stop
        stop = start + len(src)
        self.dst[start:stop] = src
        self.stop += len(src)


_OUTGOING_KEY = frozenset('-0123456789abcdefghijklmnopqrstuvwxyz')

def _check_key(key):
    _check_type('key', key, str)
    if len(key) > SCRATCH_LEN:
        raise ValueError('key is too long: {!r}'.format(key))
    if key == '' or not _OUTGOING_KEY.issuperset(key):
        raise ValueError(
            'bad key: {!r}'.format(key)
        )
    return key


def _check_val(val):
    if type(val) is not str:
        val = str(val)
    return _check_str('val', val)


def _render_headers(o, headers):
    _check_type('headers', headers, dict)
    if len(headers) > MAX_HEADER_COUNT:
        raise ValueError(
            'need len(headers) <= {}; got {}'.format(
                MAX_HEADER_COUNT, len(headers)
            )
        )
    for key in headers:
        _check_key(key)
    src = ''.join(
        '\r\n{}: {}'.format(k, _check_val(v))
        for (k, v) in sorted(headers.items()) 
    ).encode('ascii')
    o.copy_into(src)


def render_headers(dst, headers):
    o = _Output(dst)
    _render_headers(o, headers)
    return o.stop


def _render_request(o, method, uri, headers):
    _check_str('method', method)
    _check_str('uri', uri)
    line = '{} {} HTTP/1.1'.format(method, uri).encode('ascii')
    o.copy_into(line)
    _render_headers(o, headers)
    o.copy_into(b'\r\n\r\n')


def render_request(dst, method, uri, headers):
    o = _Output(dst)
    _render_request(o, method, uri, headers)
    return o.stop


def _render_response(o, status, reason, headers):
    _check_int('status', status, 100, 599)
    _check_str('reason', reason)
    line = 'HTTP/1.1 {} {}'.format(status, reason).encode('ascii')
    o.copy_into(line)
    _render_headers(o, headers)
    o.copy_into(b'\r\n\r\n')


def render_response(dst, status, reason, headers):
    o = _Output(dst)
    _render_response(o, status, reason, headers)
    return o.stop


def set_default_header(headers, key, val):
    assert isinstance(headers, dict)
    assert isinstance(key, str)
    cur = headers.setdefault(key, val)
    if val != cur:
        raise ValueError(
            '{!r} mismatch: {!r} != {!r}'.format(key, val, cur)
        )


def set_output_headers(headers, body):
    if body is None:
        return
    if type(body) is bytes:
        set_default_header(headers, 'content-length', len(body))
    elif type(body) in (Body, BodyIter):
        set_default_header(headers, 'content-length', body.content_length)
    elif type(body) in (ChunkedBody, ChunkedBodyIter):
        set_default_header(headers, 'transfer-encoding', 'chunked')
    else:
        raise TypeError(
            'bad body type: {!r}: {!r}'.format(type(body), body)
        )


class _IOBuf:
    __slots__ = ('start', 'stop', 'buf')

    def __init__(self):
        self.start = 0
        self.stop = 0
        self.buf = memoryview(bytearray(BUF_LEN))

    def peek(self, size=-1):
        stop = (self.stop if size < 0 else min(self.stop, self.start + size))
        return self.buf[self.start:stop].tobytes()

    def drain(self, size=-1):
        src = self.peek(size)
        self.start += len(src)
        if self.start == self.stop:
            self.start = 0
            self.stop = 0
        return src

    def shift_if_needed(self):
        if self.start > 0:
            src = self.drain()
            assert len(src) > 0
            self.buf[0:len(src)] = src
            self.start = 0
            self.stop = len(src)

    def get_dst(self):
        return self.buf[self.stop:]

    def copy_into_if_possible(self, src):
        assert 0 <= self.start < self.stop <= len(self.buf)
        dst = self.get_dst()
        if len(src) > len(dst):
            return False
        src_len = len(src)
        dst[0:src_len] = src
        self.stop += src_len
        return True


class SocketWrapper:
    __slots__ = (
        '_sock',
        '_sock_recv_into',
        '_sock_send',
        '_sock_close',
        '_closed',
        '_r_io',
        '_w_io',
    )

    def __init__(self, sock):
        self._sock = sock
        self._closed = False
        self._sock_close = _getcallable('sock', sock, 'close')
        self._sock_recv_into = _getcallable('sock', sock, 'recv_into')
        self._sock_send = _getcallable('sock', sock, 'send')
        self._r_io = _IOBuf()
        self._w_io = _IOBuf()

    def __del__(self):
        self.close()

    @property
    def sock(self):
        return self._sock

    @property
    def closed(self):
        return self._closed

    def close(self):
        if self._closed is not True:
            self._closed = True
            sock_close = getattr(self, '_sock_close', None)
            if sock_close is not None:
                return sock_close()

    def _recv_into(self, buf):
        added = self._sock_recv_into(buf)
        _validate_size('received', added, len(buf))
        return added

    def _found(self, index, end):
        src = self._r_io.drain(index + len(end))
        return src[0:-len(end)]

    def _not_found(self, cur, end):
        if len(cur) == 0:
            return cur
        raise ValueError(
            '{!r} not found in {!r}...'.format(end, cur[:32])
        )

    def read_until(self, size, end):
        io = self._r_io
        assert type(size) is int
        end = memoryview(end).tobytes()
        if not end:
            raise ValueError('end cannot be empty')
        if not (len(end) <= size <= len(io.buf)):
            raise ValueError(
                'need {} <= size <= {}; got {}'.format(
                    len(end), len(io.buf), size
                )
            )

        # First, search current buffer:
        cur = io.peek(size)
        index = cur.find(end)
        if index >= 0:
            return self._found(index, end)
        if len(cur) == size:
            return self._not_found(cur, end)

        # Shift buffer if needed:
        io.shift_if_needed()

        # Now search till found:
        while io.stop < size:
            added = self._recv_into(io.get_dst())
            if added == 0:
                break
            io.stop += added
            cur = io.peek(size)
            index = cur.find(end)
            if index >= 0:
                return self._found(index, end)

        # Didn't find it:
        return self._not_found(cur, end)

    def read_request(self):
        preamble = self.read_until(BUF_LEN, b'\r\n\r\n')
        return parse_request(preamble, self)

    def read_response(self, method):
        _check_method(method)
        preamble = self.read_until(BUF_LEN, b'\r\n\r\n')
        return parse_response(method, preamble, self)

    def readchunkline(self):
        line = self.read_until(4096, b'\r\n')
        return parse_chunk(line)

    def readinto(self, dst):
        dst = memoryview(dst)
        dst_len = len(dst)
        if not (1 <= dst_len <= MAX_IO_SIZE):
            raise ValueError(
                'need 1 <= len(buf) <= {}; got {}'.format(MAX_IO_SIZE, dst_len)
            )
        src = self._r_io.drain(dst_len)
        src_len = len(src)
        dst[0:src_len] = src
        added = _readinto(self._sock_recv_into, dst[src_len:])
        assert dst_len == src_len + added
        return dst_len

    def _raw_write(self, src):
        return _write(self._sock_send, src)

    def _flush(self):
        src = self._w_io.drain()
        self._raw_write(src)

    def _write(self, src):
        io = self._w_io
        if io.copy_into_if_possible(src):
            return len(src)
        else:
            self._flush()
            return self._raw_write(src)

    def _write_output(self, func, arg1, arg2, headers, body):
        io = self._w_io
        total = func(io.get_dst(), arg1, arg2, headers)
        assert total > 0
        io.stop += total
        if type(body) is bytes:
            if len(body) > MAX_IO_SIZE:
                raise ValueError(
                    'need len(body) <= {}; got {}'.format(
                        MAX_IO_SIZE, len(body)
                    )
                )
            total += self._write(body)
        elif type(body) in (Body, BodyIter, ChunkedBody, ChunkedBodyIter):
            total += body.write_to(self)
        elif body is not None:
            raise TypeError(
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )
        self._flush()
        return total

    def write_request(self, method, uri, headers, body):
        _check_method(method)
        set_output_headers(headers, body)
        return self._write_output(render_request,
            method, uri, headers, body
        )

    def write_response(self, status, reason, headers, body):
        set_output_headers(headers, body)
        return self._write_output(render_response,
            status, reason, headers, body
        )


def _check_body_state(name, state, max_state):
    assert max_state < BODY_CONSUMED
    if state <= max_state:
        return
    if state is BODY_STARTED:
        raise ValueError(
            '{}.state == BODY_STARTED, cannot start another operation'.format(
                name
            )
        )
    if state is BODY_CONSUMED:
        raise ValueError(
            '{}.state == BODY_CONSUMED, already consumed'.format(name)
        )
    if state is BODY_ERROR:
        raise ValueError(
            '{}.state == BODY_ERROR, cannot be used'.format(name)
        )
    raise Exception('bad state: {!r}'.format(state))


def _rfile_repr(rfile):
    if type(rfile) is SocketWrapper:
        return '<reader>'
    return '<rfile>'


class Body:
    __slots__ = (
        '_rfile',
        '_robj',
        '_content_length',
        '_remaining',
        '_state',
        '_chunked',
    )

    def __init__(self, rfile, content_length):
        _validate_length('content_length', content_length)
        self._rfile = rfile
        self._remaining = self._content_length = content_length
        self._state = BODY_READY
        if type(rfile) is SocketWrapper:
            self._robj = rfile
        else:
            self._robj = _getcallable('rfile', rfile, 'readinto')
        self._chunked = False

    @property
    def rfile(self):
        return self._rfile

    @property
    def content_length(self):
        return self._content_length

    @property
    def state(self):
        return self._state

    @property
    def chunked(self):
        return self._chunked

    def __repr__(self):
        return 'Body({}, {!r})'.format(
            _rfile_repr(self._rfile), self._content_length
        )

    def _do_error(self):
        self._state = BODY_ERROR
        if type(self._rfile) is SocketWrapper:
            self._rfile.close()

    def __iter__(self):
        _check_body_state('Body', self._state, BODY_READY)
        self._state = BODY_STARTED
        try:
            remaining = self._remaining
            iosize = min(remaining, IO_SIZE)
            dst = memoryview(bytearray(iosize))
            robj = self._robj
            while remaining > 0:
                size = min(remaining, iosize)
                remaining -= size
                assert remaining >= 0
                sub = dst[:size]
                _readinto_from(robj, sub)
                yield sub.tobytes()
        except:
            self._do_error()
            raise
        assert remaining == 0
        self._remaining = remaining
        self._state = BODY_CONSUMED

    def read(self, size=None):
        rsize = _validate_read_size('size', size, self._remaining)
        _check_body_state('Body', self._state, BODY_STARTED)
        self._state = BODY_STARTED
        if self._remaining == 0:
            self._state = BODY_CONSUMED
            return b''
        try:
            rsize = min(self._remaining, rsize)
            dst = memoryview(bytearray(rsize))
            _readinto_from(self._robj, dst)
            self._remaining -= rsize
            assert self._remaining >= 0
            if size is None:
                self._state = BODY_CONSUMED
            return dst.tobytes()
        except:
            self._do_error()
            raise

    def write_to(self, wfile):
        wobj = _get_wobj(wfile)
        total = sum(_write_to(wobj, data) for data in self)
        assert total == self._content_length
        return total

def _not_found(self, cur, end, readline):
    if readline:
        return self._drain(len(cur))
    if len(cur) == 0:
        return cur
    raise ValueError(
        '{!r} not found in {!r}...'.format(end, cur[:32])
    )


def _readchunk(readline, read):
    line = readline(4096)
    if type(line) is not bytes:
        raise TypeError(
            'need a {!r}; readline() returned a {!r}'.format(bytes, type(line))
        )
    if len(line) > 4096:
        raise ValueError(
            'readline() returned too many bytes: {} > {}'.format(len(line), 4096)
        )
    if line[-2:] != b'\r\n':
        raise ValueError(
            '{!r} not found in {!r}...'.format(b'\r\n', line[:32])
        )
    (size, ext) = parse_chunk(line[:-2])
    data = read(size + 2)
    if type(data) is not bytes:
        raise TypeError(
            'need a {!r}; read() returned a {!r}'.format(bytes, type(data))
        )
    if len(data) != size + 2:
        raise ValueError(
            'read() returned {} bytes, need {}'.format(len(data), size + 2)
        )
    end = data[-2:]
    if end != b'\r\n':
        raise ValueError('bad chunk data termination: {!r}'.format(end))
    return (ext, data)
    

def _readchunkline(readline):
    line = readline(4096)
    if type(line) is not bytes:
        raise TypeError(
            'need a {!r}; readline() returned a {!r}'.format(bytes, type(line))
        )
    if len(line) > 4096:
        raise ValueError(
            'readline() returned too many bytes: {} > {}'.format(len(line), 4096)
        )
    if line[-2:] != b'\r\n':
        raise ValueError(
            '{!r} not found in {!r}...'.format(b'\r\n', line[:32])
        )
    return parse_chunk(line[:-2])


def _readchunk_from(robj, readline, nopack=False):
    if type(robj) is SocketWrapper:
        (size, ext) = robj.readchunkline()
    else:
        (size, ext) = _readchunkline(readline)
    dst = memoryview(bytearray(size + 2))
    _readinto_from(robj, dst)
    if dst[-2:] != b'\r\n':
        raise ValueError(
            'bad chunk data termination: {!r}'.format(dst[-2:].tobytes())
        )
    if nopack:
        return (size, ext, dst)
    return (ext, dst[:-2].tobytes())


def readchunk(rfile):
    robj = _get_robj(rfile)
    readline = _get_readline(rfile)
    return _readchunk_from(robj, readline)


class ChunkedBody:
    __slots__ = ('_rfile', '_robj', '_readline', '_state', '_chunked')

    def __init__(self, rfile):
        self._rfile = rfile
        self._robj = _get_robj(rfile)
        self._readline = _get_readline(rfile)
        self._state = BODY_READY
        self._chunked = True

    def __repr__(self):
        return 'ChunkedBody({})'.format(_rfile_repr(self._rfile))

    @property
    def rfile(self):
        return self._rfile

    @property
    def state(self):
        return self._state

    @property
    def chunked(self):
        return self._chunked

    def _do_error(self):
        self._state = BODY_ERROR
        if type(self._rfile) is SocketWrapper:
            self._rfile.close()

    def readchunk(self):
        _check_body_state('ChunkedBody', self._state, BODY_STARTED)
        self._state = BODY_STARTED
        try:
            chunk = _readchunk_from(self._robj, self._readline)
            if len(chunk[1]) == 0:
                self._state = BODY_CONSUMED
        except:
            self._do_error()
            raise
        return chunk

    def read(self):
        _check_body_state('ChunkedBody', self._state, BODY_STARTED)
        self._state = BODY_STARTED
        try:
            total = 0
            accum = []
            while total <= MAX_IO_SIZE:
                (ext, data) = self.readchunk()
                total += len(data)
                if len(data) == 0:
                    break
                accum.append(data)
            if total > MAX_IO_SIZE:
                raise ValueError(
                    'chunks exceed MAX_IO_SIZE: {} > {}'.format(
                        total, MAX_IO_SIZE
                    )
                )
            ret =  b''.join(accum)
        except:
            self._do_error()
            raise
        self._state = BODY_CONSUMED
        return ret

    def __iter__(self):
        _check_body_state('ChunkedBody', self._state, BODY_READY)
        self._state = BODY_STARTED
        while self._state < BODY_CONSUMED:
            yield self.readchunk()

    def write_to(self, wfile):
        _check_body_state('ChunkedBody', self._state, BODY_READY)
        self._state = BODY_STARTED
        robj = self._robj
        readline = self._readline
        wobj = _get_wobj(wfile)
        readchunk_from = _readchunk_from
        format_chunk = _format_chunk
        write_to = _write_to
        total = 0
        try:
            while True:
                (size, ext, data) = readchunk_from(robj, readline, nopack=True)
                assert len(data) == size + 2 and data[-2:] == b'\r\n'
                line = format_chunk(size, ext)
                total += write_to(wobj, line)
                total += write_to(wobj, data)
                if size == 0:
                    break
        except:
            self._do_error()
            raise
        self._state = BODY_CONSUMED
        return total


class BodyIter:
    __slots__ = ('_source', '_state', '_content_length')

    def __init__(self, source, content_length):
        self._source = source
        self._state = BODY_READY
        self._content_length = _validate_length("content_length", content_length)

    def __repr__(self):
        return 'BodyIter(<source>, {})'.format(self._content_length)

    @property
    def source(self):
        return self._source

    @property
    def content_length(self):
        return self._content_length

    @property
    def state(self):
        return self._state

    def write_to(self, wfile):
        _check_body_state('BodyIter', self._state, BODY_READY)
        self._state = BODY_STARTED
        wobj = _get_wobj(wfile)
        length = self._content_length
        total = 0
        try:
            for part in self._source:
                if type(part) is not bytes:
                    _check_bytes('BodyIter source item', part)
                total += _write_to(wobj, part)
                if total > length:
                    raise ValueError(
                        'exceeds content_length: {} > {}'.format(total, length)
                    )
            if total != length:
                raise ValueError(
                    'deceeds content_length: {} < {}'.format(total, length)
                )
        except:
            self._state = BODY_ERROR
            raise
        self._state = BODY_CONSUMED
        return total


class ChunkedBodyIter:
    __slots__ = ('_source', '_state')

    def __init__(self, source):
        self._source = source
        self._state = BODY_READY

    def __repr__(self):
        return 'ChunkedBodyIter(<source>)'

    @property
    def source(self):
        return self._source

    @property
    def state(self):
        return self._state

    def write_to(self, wfile):
        _check_body_state('ChunkedBodyIter', self._state, BODY_READY)
        self._state = BODY_STARTED
        wobj = _get_wobj(wfile)
        empty = False
        total = 0
        try:
            for chunk in self._source:
                if empty:
                    raise ValueError('additional chunk after empty chunk data')
                total += _write_chunk(wobj, chunk)
                if not chunk[1]:  # Is chunk data empty?
                    empty = True
            if not empty:
                raise ValueError('final chunk data was not empty')
        except:
            self._state = BODY_ERROR
            raise
        self._state = BODY_CONSUMED
        return total

# Used to expose the RGI API to server and client applications:
api = API(Body, ChunkedBody, BodyIter, ChunkedBodyIter, Range, ContentRange)


def _check_dict(name, obj):
    if type(obj) is not dict:
        raise TypeError(
            TYPE_ERROR.format(name, dict, type(obj), obj)
        )


def _body_is_consumed(body):
    if body is None:
        return True
    assert type(body) in (Body, ChunkedBody)
    return body._state == BODY_CONSUMED


def _unpack_response(obj):
    if type(obj) is Response:
        return obj
    return _check_tuple('response', obj, 4)   

def _check_status(status):
    _validate_int('status', status)
    if not 100 <= status <= 599:
        raise ValueError(
            'need 100 <= status <= 599; got {}'.format(status)
        )

def _check_int(name, obj, _min, _max):
    _validate_int(name, obj)
    if not _min <= obj <= _max:
        raise ValueError(
            'need {} <= {} <= {}; got {}'.format(_min, name, _max, obj)
        )
    return obj


class Session:
    __slots__ = (
        '_address',
        '_credentials',
        '_max_requests',
        '_requests',
        '_store',
        '_closed',
        '_message',
    )

    def __init__(self, address, credentials=None, max_requests=None):
        if credentials is not None:
            _check_tuple('credentials', credentials, 3)
        if max_requests is None:
            max_requests=500
        self._address = address
        self._credentials = credentials
        self._max_requests = _check_int('max_requests', max_requests, 0, 75000)
        self._requests = 0
        self._store = {}
        self._closed = False
        self._message = None

    def __repr__(self):
        if self._credentials is None:
            return 'Session({!r})'.format(self._address)
        return 'Session({!r}, {!r})'.format(self._address, self._credentials)

    def __str__(self):
        if self._credentials is None:
            return repr(self._address)
        return '{!r} {!r}'.format(self._address, self._credentials)

    @property
    def address(self):
        return self._address

    @property
    def credentials(self):
        return self._credentials

    @property
    def max_requests(self):
        return self._max_requests

    @property
    def requests(self):
        return self._requests

    @property
    def store(self):
        return self._store

    @property
    def closed(self):
        return self._closed

    @property
    def message(self):
        return self._message

    def close(self, message):
        self._closed = True
        if self._message is None:
            self._message = message

    def _response_complete(self, status, reason):
        if status >= 400 and status not in (404, 409, 412):
            self.close('{} {}'.format(status, reason))
        self._requests += 1
        if self._requests >= self._max_requests:
            self.close('max_requests')


def _handle_requests_inner(wrapper, app, session, sock):
    _check_type2('session', session, Session)
    assert session.requests == session._requests == 0
    while not session._closed:
        request = wrapper.read_request()
        response = app(session, request, api)
        (status, reason, headers, body) = _unpack_response(response)
        _check_status(status)

        # Make sure application fully consumed request body:
        if not _body_is_consumed(request.body):
            raise ValueError(
                'request body not consumed: {!r}'.format(request.body)
            )

        # FIXME: when 200 <= status <= 299, we should consider requiring that
        # the response body for a GET request not be None

        # Make sure HEAD requests are properly handled:
        if request.method == 'HEAD' and body is not None:
            raise TypeError(
                'request method is HEAD, but response body is not None: {!r}'.format(
                    type(body)
                )
            )
            # FIXME: when 200 <= status <= 299, we should consider requiring
            # a 'content-length' or 'transfer-encoding' header in the response
            # to a HEAD request

        # Write response:
        wrapper.write_response(status, reason, headers, body)

        # Update request counter, possibly close based on status:
        session._response_complete(status, reason)


def _handle_requests(app, session, sock):
    wrapper = SocketWrapper(sock)
    try:
        return _handle_requests_inner(wrapper, app, session, sock)
    finally:
        wrapper.close()
        


class Connection:
    __slots__ = (
        'sock',
        'base_headers',
        '_wrapper',
        '_response_body',
        '_api',
    )

    def __init__(self, sock, base_headers):
        self.sock = sock
        self._wrapper = SocketWrapper(sock)
        if base_headers is not None:
            _check_type2('base_headers', base_headers, tuple)
        self.base_headers = base_headers
        self._response_body = None
        self._api = api

    @property
    def closed(self):
        return self._wrapper.closed

    @property
    def api(self):
        return self._api

    @property
    def bodies(self):
        """
        Deprecated alias for `Connection.api`.

        This attribute is deprecated and will be remove at some point in a
        future Degu release.  Please use the `Connection.api` attribute instead.

        FIXME: Remove this attribute when the time is right.
        """
        return self._api

    def close(self):
        return self._wrapper.close()

    def request(self, method, uri, headers, body):
        if self._wrapper.closed is not False:
            raise ValueError('Connection is closed')
        try:
            _check_method(method)
            if body is not None and method not in {'PUT', 'POST'}:
                raise ValueError(
                    'when method is {!r}, body must be None; got a {!r}'.format(
                        method, type(body)
                    )
                )
            if not _body_is_consumed(self._response_body):
                raise ValueError(
                    'response body not consumed: {!r}'.format(self._response_body)
                )
            if self.base_headers is not None:
                headers.update(self.base_headers)
            self._wrapper.write_request(method, uri, headers, body)
            response = self._wrapper.read_response(method)
            self._response_body = response.body
            return response
        except Exception:
            self.close()
            raise

    def put(self, uri, headers, body):
        return self.request('PUT', uri, headers, body)

    def post(self, uri, headers, body):
        return self.request('POST', uri, headers, body)

    def get(self, uri, headers):
        return self.request('GET', uri, headers, None)

    def head(self, uri, headers):
        return self.request('HEAD', uri, headers, None)

    def delete(self, uri, headers):
        return self.request('DELETE', uri, headers, None)

    def get_range(self, uri, headers, start, stop):
        set_default_header(headers, 'range', Range(start, stop))
        return self.request('GET', uri, headers, None)



################################################################################
# degu.applib components

def _router_depth_error():
    raise ValueError(
        'Router: max appmap depth {!r} exceeded'.format(ROUTER_MAX_DEPTH)
    )


def _router_check_appmap(appmap, depth):
    assert isinstance(depth, int) and depth >= 0
    if depth >= ROUTER_MAX_DEPTH:
        _router_depth_error()
    _check_dict('appmap', appmap)
    for (key, value) in appmap.items():
        if key is not None:
            _check_str('appmap key', key, 0)
        if type(value) is dict:
            _router_check_appmap(value, depth + 1)
        elif not callable(value):
            raise TypeError(
                'appmap[{!r}]: value not callable: {!r}'.format(key, value)
            )


class Router:
    """
    Generic RGI routing middleware.

    For example:

    >>> def foo_app(session, request, api):
    ...     return (200, 'OK', {}, b'foo')
    ... 
    >>> def bar_app(session, request, api):
    ...     return (200, 'OK', {}, b'bar')
    ...
    >>> from degu.applib import Router
    >>> router = Router({'foo': foo_app, 'bar': bar_app})

    """

    __slots__ = ('appmap',)

    def __init__(self, appmap):
        _router_check_appmap(appmap, 0)
        self.appmap = appmap

    def __call__(self, session, request, api):
        _check_type('request', request, Request)
        appmap = self.appmap
        for depth in range(ROUTER_MAX_DEPTH):
            handler = appmap.get(request.shift_path())
            if handler is None:
                return (410, 'Gone', {}, None)
            if not isinstance(handler, dict):
                return handler(session, request, api)
            appmap = handler
        _router_depth_error()


class ProxyApp:
    """
    Generic RGI reverse-proxy application.
    """

    __slots__ = ('client', 'key')

    def __init__(self, client, key='conn'):
        self.client = client
        self.key = key

    def __call__(self, session, request, api):
        _check_type('session', session, Session)
        _check_type('request', request, Request)
        conn = session.store.get(self.key)
        if conn is None:
            conn = self.client.connect()
            session.store[self.key] = conn
        return conn.request(
            request.method,
            request.build_proxy_uri(),
            request.headers,
            request.body,
        )

