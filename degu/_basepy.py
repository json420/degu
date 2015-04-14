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
Pure-Python equivalent of the `degu._base` C extension.

Although `degu._basepy` is automatically imported as a fall-back when the
`degu._base` C extension isn't available, this Python implementation really
isn't meant for production use (mainly because it's much, much slower).

This is a reference implementation whose purpose is only to help enforce the
correctness of the C implementation.
"""

from collections import namedtuple
import socket
import sys


TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

_MAX_LINE_SIZE = 4096  # Max length of line in HTTP preamble, including CRLF
MIN_PREAMBLE     =  4096  #  4 KiB
DEFAULT_PREAMBLE = 32768  # 32 KiB
MAX_PREAMBLE     = 65536  # 64 KiB
MAX_IO_SIZE = 16777216  # 16 MiB
MAX_LENGTH = 9999999999999999
MAX_READ_SIZE = 16777216  # 16 MiB
IO_SIZE = 1048576  # 1 MiB

_METHODS = {
    b'GET': 'GET',
    b'PUT': 'PUT',
    b'POST': 'POST',
    b'HEAD': 'HEAD',
    b'DELETE': 'DELETE',
}

_OK = 'OK'


BodiesType = Bodies = namedtuple('Bodies',
    'Body BodyIter ChunkedBody ChunkedBodyIter'
)
RequestType = Request = namedtuple('Request',
    'method uri headers body script path query'
)
ResponseType = Response = namedtuple('Response', 'status reason headers body')


class EmptyPreambleError(ConnectionError):
    pass


################    BEGIN GENERATED TABLES    ##################################
NAME = frozenset(
    b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
)

_DIGIT = b'0123456789'
_ALPHA = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_PATH  = b'+-.:_~'
_QUERY = b'%&='
_URI   = b'/?'
_SPACE = b' '
_VALUE = b'"\'()*,;[]'

DIGIT  = frozenset(_DIGIT)
PATH   = frozenset(_DIGIT + _ALPHA + _PATH)
QUERY  = frozenset(_DIGIT + _ALPHA + _PATH + _QUERY)
URI    = frozenset(_DIGIT + _ALPHA + _PATH + _QUERY + _URI)
REASON = frozenset(_DIGIT + _ALPHA + _SPACE)
VALUE  = frozenset(_DIGIT + _ALPHA + _PATH + _QUERY + _URI + _SPACE + _VALUE)
################    END GENERATED TABLES      ##################################


KEY = frozenset('-0123456789abcdefghijklmnopqrstuvwxyz')


def _getcallable(objname, obj, name):
    attr = getattr(obj, name)
    if not callable(attr):
        raise TypeError('{}.{}() is not callable'.format(objname, name))
    return attr


################################################################################
# Header parsing:

def _validate_length(name, length):
    if type(length) is not int:
        raise TypeError(
            TYPE_ERROR.format(name, int, type(length), length)
        )
    if (length < 0):
        raise OverflowError("can't convert negative int to unsigned")
    if (length >= 2**64):
        raise OverflowError('int too big to convert')
    if (length > MAX_LENGTH):
        raise ValueError(
            'need 0 <= {} <= {}; got {}'.format(name, MAX_LENGTH, length)
        )
    return length


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

    def __get_this(self, other):
        if type(other) is tuple or type(other) is type(self):
            return (self._start, self._stop)
        if type(other) is str:
            return str(self)

    def __lt__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this < other

    def __le__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this <= other

    def __eq__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this == other

    def __ne__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this != other

    def __gt__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this > other

    def __ge__(self, other):
        this = self.__get_this(other)
        if this is None:
            return NotImplemented 
        return this >= other


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
    if VALUE.issuperset(src):
        return src.decode('ascii')
    raise ValueError('bad bytes in header value: {!r}'.format(src))


def parse_content_length(src):
    assert isinstance(src, bytes)
    if len(src) < 1:
        raise ValueError('content-length is empty')
    if len(src) > 16:
        raise ValueError(
            'content-length too long: {!r}...'.format(src[:16])
        )
    if not DIGIT.issuperset(src):
        raise ValueError(
            'bad bytes in content-length: {!r}'.format(src)
        )
    if src[0:1] == b'0' and src != b'0':
        raise ValueError(
            'content-length has leading zero: {!r}'.format(src)
        )
    return int(src)

def _parse_decimal(src):
    if len(src) < 1 or len(src) > 16:
        return -1
    if not DIGIT.issuperset(src):
        return -1
    if src[0:1] == b'0' and src != b'0':
        return -1
    return int(src)


def _raise_bad_range(src):
    raise ValueError('bad range: {!r}'.format(src))


def parse_range(src):
    assert isinstance(src, bytes)
    if len(src) < 9 or len(src) > 39 or src[0:6] != b'bytes=':
        _raise_bad_range(src)
    inner = src[6:]
    parts = inner.split(b'-', 1)
    if len(parts) != 2:
        _raise_bad_range(src)
    start = _parse_decimal(parts[0])
    end = _parse_decimal(parts[1])
    if start < 0 or end < start:
        _raise_bad_range(src)
    return Range(start, end + 1)


def _parse_header_lines(header_lines):
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
    if (flags & 4) and (flags & 3):
        raise ValueError(
            'cannot include range header and content-length/transfer-encoding'
        )
    return headers


def parse_headers(src):
    if src == b'':
        return {}
    return _parse_header_lines(src.split(b'\r\n'))



################################################################################
# Request parsing:

def _parse_method(src):
    assert isinstance(src, bytes)
    method = _METHODS.get(src)
    if method is None:
        raise ValueError('bad HTTP method: {!r}'.format(src))
    return method


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


def parse_uri(src):
    if not src:
        raise ValueError('uri is empty')
    if not URI.issuperset(src):
        raise ValueError('bad bytes in uri: {!r}'.format(src))
    uri = src.decode('ascii')
    parts = src.split(b'?', 1)
    path = _parse_path(parts[0])
    if len(parts) == 1:
        query = None
    else:
        query = _parse_query(parts[1])
    # (uri, script, path, query):
    return (uri, [], path, query)


def parse_request_line(line):
    if len(line) < 14:
        raise ValueError('request line too short: {!r}'.format(line))
    if line[-9:] != b' HTTP/1.1':
        raise ValueError('bad protocol in request line: {!r}'.format(line[-9:]))
    src = line[:-9]
    items = src.split(b' /', 1)
    if len(items) < 2:
        raise ValueError('bad request line: {!r}'.format(line))
    method = _parse_method(items[0])
    (uri, script, path, query) = parse_uri(b'/' + items[1])
    return (method, uri, script, path, query)


def _parse_request(preamble, rfile, _Body, _ChunkedBody):
    if preamble == b'':
        raise EmptyPreambleError('request preamble is empty')
    (first_line, *header_lines) = preamble.split(b'\r\n')
    (method, uri, script, path, query) = parse_request_line(first_line)
    headers = _parse_header_lines(header_lines)
    if 'content-length' in headers:
        body = _Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = _ChunkedBody(rfile)
    else:
        body = None
    return Request(method, uri, headers, body, script, path, query)


def parse_request(preamble, rfile, bodies):
    return _parse_request(preamble, rfile, bodies.Body, bodies.ChunkedBody)



################################################################################
# Response parsing:

def _parse_status(src):
    if DIGIT.issuperset(src):
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


def _parse_response(method, preamble, rfile, _Body, _ChunkedBody):
    if preamble == b'':
        raise EmptyPreambleError('response preamble is empty')
    (first_line, *header_lines) = preamble.split(b'\r\n')
    (status, reason) = parse_response_line(first_line)
    headers = _parse_header_lines(header_lines)
    if method == 'HEAD':
        body = None
    elif 'content-length' in headers:
        body = _Body(rfile, headers['content-length'])
    elif 'transfer-encoding' in headers:
        body = _ChunkedBody(rfile)
    else:
        body = None
    return Response(status, reason, headers, body)


def parse_response(method, preamble, rfile, bodies):
    method = parse_method(method)
    return _parse_response(
        method, preamble, rfile, bodies.Body, bodies.ChunkedBody
    )


################################################################################
# Formatting:

def format_headers(headers):
    if type(headers) is not dict:
        raise TypeError(
            TYPE_ERROR.format('headers', dict, type(headers), headers)
        )
    lines = []
    for (key,  value) in headers.items():
        if type(key) is not str:
            raise TypeError(
                TYPE_ERROR.format('key', str, type(key), key)
            )
        if not KEY.issuperset(key):
            raise ValueError('bad key: {!r}'.format(key))
        lines.append('{}: {}\r\n'.format(key, value))
    lines.sort()
    return ''.join(lines)


def format_request(method, uri, headers):
    lines = ['{} {} HTTP/1.1\r\n'.format(method, uri)]
    if headers:
        header_lines = ['{}: {}\r\n'.format(*kv) for kv in headers.items()]
        header_lines.sort()
        lines.extend(header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode()


def format_response(status, reason, headers):
    lines = ['HTTP/1.1 {} {}\r\n'.format(status, reason)]
    if headers:
        header_lines = ['{}: {}\r\n'.format(*kv) for kv in headers.items()]
        header_lines.sort()
        lines.extend(header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode()




################################################################################
# Reader:

class Reader:
    __slots__ = (
        '_sock_shutdown',
        '_sock_recv_into',
        '_Body',
        '_ChunkedBody',
        '_rawtell',
        '_rawbuf',
        '_start',
        '_buf',
        '_closed',
    )

    def __init__(self, sock, bodies, size=DEFAULT_PREAMBLE):
        assert isinstance(size, int)
        if not (MIN_PREAMBLE <= size <= MAX_PREAMBLE):
            raise ValueError(
                'need {!r} <= size <= {!r}; got {!r}'.format(
                    MIN_PREAMBLE, MAX_PREAMBLE, size
                )
            )
        self._sock_shutdown = _getcallable('sock', sock, 'shutdown')
        self._sock_recv_into = _getcallable('sock', sock, 'recv_into')
        self._Body = _getcallable('bodies', bodies, 'Body')
        self._ChunkedBody = _getcallable('bodies', bodies, 'ChunkedBody')
        self._rawtell = 0
        self._rawbuf = memoryview(bytearray(size))
        self._start = 0
        self._buf = b''
        self._closed = False

    def close(self):
        if self._closed is True:
            return None
        assert self._closed is False
        self._closed = True
        return self._sock_shutdown(socket.SHUT_RDWR)

    def rawtell(self):
        return self._rawtell

    def tell(self):
        return self._rawtell - len(self._buf)

    def _recv_into(self, buf):
        added = self._sock_recv_into(buf)
        if type(added) is not int:
            raise TypeError(
                'need a {!r}; recv_into() returned a {!r}: {!r}'.format(
                    int, type(added), added
                )
            )
        if added < 0:
            raise OverflowError("can't convert negative value to size_t")
        if added > sys.maxsize * 2 + 1:
            raise OverflowError('Python int too large to convert to C size_t')
        if not (0 <= added <= len(buf)):
            raise OSError(
                'need 0 <= size <= {}; recv_into() returned {}'.format(
                    len(buf), added
                )
            )
        self._rawtell += added
        return added

    def _update(self, start, size):
        """
        Valid transitions::

            ===========================
            -->|<--            |  Empty
               |<---- buf <--  |  Shift
               |      buf ---->|  Fill
               |  --> buf      |  Drain
            ===========================
        """
        # Check previous state:
        assert 0 <= self._start <= self._start + len(self._buf) <= len(self._rawbuf)

        # Check new state:
        assert 0 <= start <= start + size <= len(self._rawbuf)

        # _update() should only be called when there is a change:
        assert start != self._start or size != len(self._buf)

        # Check that previous to new is one of the four valid transitions:
        if size == 0:
            # empty
            assert start == 0
            assert len(self._buf) > 0
        elif size == len(self._buf):
            # shift
            assert size > 0
            assert start == 0
            assert self._start > 0
        elif size > len(self._buf):
            # fill
            assert size > 0
            assert start == self._start == 0
        elif size < len(self._buf):
            # drain
            assert size > 0
            assert start + size == self._start + len(self._buf)
        else:
            raise ValueError(
                'invalid buffer update: ({},{}) --> ({}, {})'.format(
                    self._start, len(self._buf), start, size
                )
            )

        # Update start, buf:
        self._start = start
        self._buf = self._rawbuf[start:start+size].tobytes()

    def expose(self):
        return self._rawbuf.tobytes()

    def peek(self, size):
        assert isinstance(size, int)
        if size < 0:
            return self._buf
        return self._buf[0:size]

    def drain(self, size):
        avail = len(self._buf)
        src = self.peek(size)
        if len(src) == 0:
            return src
        if len(src) == avail:
            self._update(0, 0)
        else:
            self._update(self._start + len(src), avail - len(src))
        return src

    def _found(self, index, end, strip_end):
        src = self.drain(index + len(end))
        if strip_end:
            return src[0:-len(end)]
        return src

    def _not_found(self, cur, end, always_drain):
        if always_drain:
            return self.drain(len(cur))
        if len(cur) == 0:
            return cur
        raise ValueError(
            '{!r} not found in {!r}...'.format(end, cur[:32])
        )

    def read_until(self, size, end, always_drain=False, strip_end=False):
        end = memoryview(end).tobytes()
        assert type(size) is int
        assert type(strip_end) is bool
        assert type(always_drain) is bool

        if not end:
            raise ValueError('end cannot be empty')
        if not (len(end) <= size <= len(self._rawbuf)):
            raise ValueError(
                'need {} <= size <= {}; got {}'.format(
                    len(end), len(self._rawbuf), size
                )
            )
        if always_drain and strip_end:
            raise ValueError(
                '`always_drain` and `strip_end` cannot both be True'
            )

        # First, search current buffer:
        cur = self.peek(size)
        index = cur.find(end)
        if index >= 0:
            return self._found(index, end, strip_end)
        if len(cur) == size:
            return self._not_found(cur, end, always_drain)

        # Shift buffer if needed:
        if self._start > 0:
            assert len(cur) > 0
            self._rawbuf[0:len(cur)] = cur
            self._update(0, len(cur))

        # Now search till found:
        start = len(cur)
        while start < size:
            dst = self._rawbuf[start:]
            added = self._recv_into(dst)
            if added == 0:
                break
            start += added
            self._update(0, start)
            cur = self.peek(size)
            index = cur.find(end)
            if index >= 0:
                return self._found(index, end, strip_end)

        # Didn't find it:
        return self._not_found(cur, end, always_drain)

    def readline(self, size):
        return self.read_until(size, b'\n', always_drain=True)

    def read_request(self):
        preamble = self.read_until(
            len(self._rawbuf), b'\r\n\r\n', strip_end=True
        )
        return _parse_request(preamble, self, self._Body, self._ChunkedBody)

    def read_response(self, method):
        method = parse_method(method)
        preamble = self.read_until(
            len(self._rawbuf), b'\r\n\r\n', strip_end=True
        )
        return _parse_response(
            method, preamble, self, self._Body, self._ChunkedBody
        )
        
    def read(self, size):
        assert isinstance(size, int)
        if not (0 <= size <= MAX_IO_SIZE):
            raise ValueError(
                'need 0 <= size <= {}; got {}'.format(MAX_IO_SIZE, size)
            )
        if size == 0:
            return b''
        src = self.drain(size)
        src_len = len(src)
        if src_len == size:
            return src
        assert src_len < size
        dst = memoryview(bytearray(size))
        dst[0:src_len] = src
        stop = src_len
        while stop < size:
            added = self._recv_into(dst[stop:])
            if added <= 0:
                assert added == 0
                break
            assert stop + added <= size
            stop += added
        return dst[:stop].tobytes()

    def readinto(self, dst):
        dst = memoryview(dst)
        dst_len = len(dst)
        if not (1 <= dst_len <= MAX_IO_SIZE):
            raise ValueError(
                'need 1 <= len(buf) <= {}; got {}'.format(MAX_IO_SIZE, dst_len)
            )
        src = self.drain(dst_len)
        src_len = len(src)
        dst[0:src_len] = src
        start = src_len
        while start < dst_len:
            added = self._recv_into(dst[start:])
            if added <= 0:
                assert added == 0
                break
            start += added
        return start


################################################################################
# Writer:

def set_default_header(headers, key, val):
    assert isinstance(headers, dict)
    assert isinstance(key, str)
    assert isinstance(val, (str, int))
    cur = headers.setdefault(key, val)
    if val != cur:
        raise ValueError(
            '{!r} mismatch: {!r} != {!r}'.format(key, val, cur)
        )


class Writer:
    __slots__ = (
        '_sock_shutdown',
        '_sock_send',
        '_length_types',
        '_chunked_types',
        '_tell',
        '_closed',
    )

    def __init__(self, sock, bodies):
        self._sock_shutdown = _getcallable('sock', sock, 'shutdown')
        self._sock_send = _getcallable('sock', sock, 'send')
        self._length_types = (bodies.Body, bodies.BodyIter)
        self._chunked_types = (bodies.ChunkedBody, bodies.ChunkedBodyIter)
        self._tell = 0
        self._closed = False

    def close(self):
        if self._closed is True:
            return None
        assert self._closed is False
        self._closed = True
        return self._sock_shutdown(socket.SHUT_RDWR)

    def tell(self):
        return self._tell

    def flush(self):
        pass

    def _write1(self, buf):
        size = self._sock_send(buf)
        if type(size) is not int:
            raise TypeError(
                'need a {!r}; send() returned a {!r}: {!r}'.format(
                    int, type(size), size
                )
            )
        if size < 0:
            raise OverflowError("can't convert negative value to size_t")
        if size > sys.maxsize * 2 + 1:
            raise OverflowError('Python int too large to convert to C size_t')
        if size > len(buf):
            raise OSError(
                'need 0 <= size <= {!r}; send() returned {!r}'.format(len(buf), size)
            )
        return size

    def write(self, buf):
        buf = memoryview(buf)
        size = 0
        while size < len(buf):
            added = self._write1(buf[size:])
            if added == 0:
                break
            size += added
        if size != len(buf):
            raise OSError(
                'expected {!r}; send() returned {!r}'.format(len(buf), size)
            )
        self._tell += size
        return size

    def set_default_headers(self, headers, body):
        assert isinstance(headers, dict)
        if type(body) is bytes:
            set_default_header(headers, 'content-length', len(body))
        elif isinstance(body, self._length_types):
            set_default_header(headers, 'content-length', body.content_length)
        elif isinstance(body, self._chunked_types):
            set_default_header(headers, 'transfer-encoding', 'chunked')
        elif body is not None:
            raise TypeError(
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )

    def write_output(self, preamble, body):
        if body is None:
            return self.write(preamble)
        if type(body) is bytes:
            return self.write(preamble + body)
        self.write(preamble)
        orig_tell = self.tell()
        total = body.write_to(self)
        if type(total) is not int:
            raise TypeError(
                'need a {!r}; write_to() returned a {!r}: {!r}'.format(
                    int, type(total), total
                )
            )
        if total < 0:
            raise OverflowError("can't convert negative int to unsigned")
        if total >= 2**64:
            raise OverflowError('int too big to convert')
        delta = self.tell() - orig_tell
        if delta != total:
            raise ValueError(
                '{!r} bytes were written, but write_to() returned {!r}'.format(
                    delta, total
                )
            )
        return total + len(preamble)

    def write_request(self, method, uri, headers, body):
        method = parse_method(method)
        self.set_default_headers(headers, body)
        preamble = format_request(method, uri, headers)
        return self.write_output(preamble, body)

    def write_response(self, status, reason, headers, body):
        self.set_default_headers(headers, body)
        preamble = format_response(status, reason, headers)
        return self.write_output(preamble, body)


class Body:
    chunked = False
    __slots__ = ('rfile', 'content_length', 'io_size', 'closed', '_remaining')

    def __init__(self, rfile, content_length, io_size=None):
        if type(content_length) is not int:
            raise TypeError(TYPE_ERROR.format(
                'content_length', int, type(content_length), content_length)
            )
        if content_length < 0:
            raise OverflowError("can't convert negative int to unsigned")
        if io_size is None:
            io_size = IO_SIZE
        else:
            if type(io_size) is not int:
                raise TypeError(
                    TYPE_ERROR.format('io_size', int, type(io_size), io_size)
                )
            if not (4096 <= io_size <= MAX_READ_SIZE):
                raise ValueError(
                    'need 4096 <= io_size <= {}; got {}'.format(
                        MAX_READ_SIZE, io_size
                    )
                )
            if io_size & (io_size - 1):
                raise ValueError(
                    'io_size must be a power of 2; got {}'.format(io_size)
                )
        self.rfile = rfile
        self.content_length = content_length
        self.io_size = io_size
        self.closed = False
        self._remaining = content_length

    def __repr__(self):
        return '{}(<rfile>, {!r})'.format(
            self.__class__.__name__, self.content_length
        )

    def __iter__(self):
        if self.closed:
            raise ValueError('Body.closed, already consumed')
        remaining = self._remaining
        if remaining != self.content_length:
            raise Exception('cannot mix Body.read() with Body.__iter__()')
        self._remaining = 0
        io_size = self.io_size
        read = self.rfile.read
        while remaining > 0:
            readsize = min(remaining, io_size)
            remaining -= readsize
            assert remaining >= 0
            data = read(readsize)
            if len(data) != readsize:
                self.rfile.close()
                raise ValueError(
                    'underflow: {} < {}'.format(len(data), readsize)
                )
            yield data
        self.closed = True

    # FIXME: Add 2nd, max_size=None optional keyword argument
    def read(self, size=None):
        if self.closed:
            raise ValueError('Body.closed, already consumed')
        if self._remaining <= 0:
            self.closed = True
            return b''
        if size is None:
            read = self._remaining
            if read > MAX_READ_SIZE:
                raise ValueError(
                    'max read size exceeded: {} > {}'.format(read, MAX_READ_SIZE)
                )
        else:
            if type(size) is not int:
                raise TypeError(
                    TYPE_ERROR.format('size', int, type(size), size) 
                )
            if not (0 <= size <= MAX_READ_SIZE):
                raise ValueError(
                    'need 0 <= size <= {}; got {}'.format(MAX_READ_SIZE, size)
                )
            read = min(self._remaining, size)
        data = self.rfile.read(read)
        if len(data) != read:
            # Security note: if application-level code is being overly general
            # with their exception handling, they might continue to use a
            # connection even after an ValueError which could create a
            # request/response stream state inconsistency.  So in this
            # circumstance, we close the rfile, but we do *not* set Body.closed
            # to True (which means "fully consumed") because the body was not in
            # fact fully read. 
            self.rfile.close()
            raise ValueError(
                'underflow: {} < {}'.format(len(data), read)
            )
        self._remaining -= read
        assert self._remaining >= 0
        if size is None:
            # Entire body was read at once, so close:
            self.closed = True
        return data

    def write_to(self, wfile):
        total = sum(wfile.write(data) for data in self)
        assert total == self.content_length
        wfile.flush()
        return total

