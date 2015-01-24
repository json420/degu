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

__all__ = (
    '_MAX_LINE_SIZE',
    '_MAX_HEADER_COUNT',
    'EmptyPreambleError',
)

_MAX_LINE_SIZE = 4096  # Max length of line in HTTP preamble, including CRLF
_MAX_HEADER_COUNT = 20

READER_BUFFER_SIZE = 65536  # 64 KiB
MAX_PREAMBLE_SIZE  = 32768  # 32 KiB

GET = 'GET'
PUT = 'PUT'
POST = 'POST'
HEAD = 'HEAD'
DELETE = 'DELETE'
OK = 'OK'



################    BEGIN GENERATED TABLES    ##################################
NAME = frozenset(
    b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
)

_DIGIT = b'0123456789'
_ALPHA = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
_PATH  = b'-.:_~'
_QUERY = b'%&+='
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


def _decode(src, allowed, message):
    if allowed.issuperset(src):
        return src.decode('ascii')
    raise ValueError(message.format(src))


def parse_method(method):
    if isinstance(method, str):
        method = method.encode()
    if method == b'GET':
        return GET
    if method == b'PUT':
        return PUT
    if method == b'POST':
        return POST
    if method == b'HEAD':
        return HEAD
    if method == b'DELETE':
        return DELETE
    raise ValueError('bad HTTP method: {!r}'.format(method))


def _parse_path(src):
    if not src:
        raise ValueError('path is empty')
    if src[0:1] != b'/':
        raise ValueError("path[0:1] != b'/': {!r}".format(src))
    if b'//' in src:
        raise ValueError("b'//' in path: {!r}".format(src))

    if src == b'/':
        return []
    return [
        _decode(c, PATH, 'bad bytes in path component: {!r}')
        for c in src[1:].split(b'/')
    ]


def parse_uri(src):
    if not src:
        raise ValueError('uri is empty')

    uri = _decode(src, URI, 'bad bytes in uri: {!r}')
    parts = src.split(b'?', 1)
    assert len(parts) in (1, 2)
    path = _parse_path(parts[0])
    if len(parts) == 1:
        query = None
    else:
        query = _decode(parts[1], QUERY, 'bad bytes in query: {!r}')
    return {
        'uri': uri,
        'script': [],
        'path': path,
        'query': query,
    }


def _decode_value(src, message):
    """
    Used to decode and validate header values, plus the preamble first line.
    """
    text = None
    try:
        text = src.decode('ascii')
    except ValueError:
        pass
    if text is None or not text.isprintable():
        raise ValueError(message.format(src))
    return text


def parse_header_name(buf):
    """
    Used to decode, validate, and case-fold header keys.
    """
    if len(buf) < 1:
        raise ValueError('header name is empty')
    if len(buf) > 32:
        raise ValueError('header name too long: {!r}...'.format(buf[:32]))
    if NAME.issuperset(buf):
        return buf.decode('ascii').lower()
    raise ValueError('bad bytes in header name: {!r}'.format(buf))


def _decode_uri(src):
    if URI.issuperset(src):
        return src.decode()
    raise ValueError(
        'bad uri in request line: {!r}'.format(src)
    )


def parse_content_length(buf):
    assert isinstance(buf, bytes)
    if len(buf) < 1:
        raise ValueError('content-length is empty')
    if len(buf) > 16:
        raise ValueError(
            'content-length too long: {!r}...'.format(buf[:16])
        )
    if not DIGIT.issuperset(buf):
        raise ValueError(
            'bad bytes in content-length: {!r}'.format(buf)
        )
    if buf[0:1] == b'0' and buf != b'0':
        raise ValueError(
            'content-length has leading zero: {!r}'.format(buf)
        )
    value = int(buf)
    if value > 9007199254740992:
        raise ValueError(
            'content-length value too large: {!r}'.format(value)
        )
    return value


class EmptyPreambleError(ConnectionError):
    pass


def parse_response_line(line):
    if isinstance(line, str):
        line = line.encode()

    if len(line) < 15:
        raise ValueError('response line too short: {!r}'.format(line))
    if line[0:9] != b'HTTP/1.1 ' or line[12:13] != b' ':
        raise ValueError('bad response line: {!r}'.format(line))

    # status:
    status = None
    try:
        status = int(line[9:12])
    except ValueError:
        pass
    if status is None or not (100 <= status <= 599):
        raise ValueError('bad status: {!r}'.format(line[9:12]))

    # reason:
    if line[13:] == b'OK':
        reason = OK
    else:
        reason = _decode_value(line[13:], 'bad reason in response line: {!r}')

    # Return (status, reason) 2-tuple:
    return (status, reason)


def parse_request_line(line):
    if len(line) < 14:
        raise ValueError('request line too short: {!r}'.format(line))
    if line[-9:] != b' HTTP/1.1':
        raise ValueError('bad protocol in request line: {!r}'.format(line[-9:]))
    src = line[:-9]
    items = src.split(b' /', 1)
    if len(items) < 2:
        raise ValueError('bad request line: {!r}'.format(line))
    request = {'method': parse_method(items[0])}
    request.update(parse_uri(b'/' + items[1]))
    return request


def _parse_header_lines(header_lines):
    headers = {}
    for line in header_lines:
        (key, value) = (None, None)
        parts = line.split(b': ', 1)
        if len(parts) >= 2:
            (key, value) = parts
        if not (key and value):
            raise ValueError('bad header line: {!r}'.format(line))
        key = parse_header_name(key)
        value = _decode_value(value, 'bad bytes in header value: {!r}')
        if headers.setdefault(key, value) is not value:
            raise ValueError(
                'duplicate header: {!r}'.format(line)
            )
    cl = headers.get('content-length')
    if cl is not None:
        headers['content-length'] = parse_content_length(cl.encode())
        if 'transfer-encoding' in headers:
            raise ValueError(
                'cannot have both content-length and transfer-encoding headers'
            )
    elif 'transfer-encoding' in headers:
        if headers['transfer-encoding'] != 'chunked':
            raise ValueError(
                'bad transfer-encoding: {!r}'.format(
                    headers['transfer-encoding'].encode()
                )
            )
    return headers


def parse_request(preamble):
    (line, *header_lines) = preamble.split(b'\r\n')
    request = parse_request_line(line)
    request['headers'] = _parse_header_lines(header_lines)
    return request


def parse_response(preamble):
    (line, *header_lines) = preamble.split(b'\r\n')
    (status, reason) = parse_response_line(line)
    headers = _parse_header_lines(header_lines)
    return (status, reason, headers)


class Reader:
    __slots__ = ('sock', 'bodies', '_rawtell', '_rawbuf', '_start', '_buf')

    def __init__(self, sock, bodies):
        if not callable(sock.recv_into):
            raise TypeError('sock.recv_into() is not callable')
        if not callable(bodies.Body):
            raise TypeError('bodies.Body is not callable')
        if not callable(bodies.ChunkedBody):
            raise TypeError('bodies.ChunkedBody is not callable')
        self.sock = sock
        self.bodies = bodies
        self._rawtell = 0
        self._rawbuf = memoryview(bytearray(2**16))
        self._start = 0
        self._buf = b''

    def rawtell(self):
        return self._rawtell

    def tell(self):
        return self._rawtell - len(self._buf)

    def _sock_recv_into(self, buf):
        added = self.sock.recv_into(buf)
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

    def start_stop(self):
        return (self._start, self._start + len(self._buf))

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

    def fill(self, size):
        assert isinstance(size, int)
        if not (0 <= size <= len(self._rawbuf)):
            raise ValueError(
                'need 0 <= size <= {}; got {}'.format(len(self._rawbuf), size)
            )
        cur = self.peek(size)
        if len(cur) == size:
            return cur
        assert len(cur) < size
        assert len(cur) == len(self._buf)
        if self._start > 0:
            assert len(cur) > 0
            self._rawbuf[0:len(cur)] = cur
            self._update(0, len(cur))
        assert self._start == 0
        assert len(self._buf) == len(cur)
        added = self._sock_recv_into(self._rawbuf[len(cur):])
        assert added >= 0
        if added > 0:
            self._update(0, len(cur) + added)
        return self.peek(size)

    def fill_until(self, size, end):
        # First, search current buffer:
        cur = self.peek(size)
        index = cur.find(end)
        if index >= 0:
            return (True, self.peek(index + len(end)))
        if len(cur) >= size:
            assert len(cur) == size
            return (False, cur)

        # Shift buffer if needed:
        if self._start > 0:
            assert len(cur) > 0
            self._rawbuf[0:len(cur)] = cur
            self._update(0, len(cur))

        # Now search till found:
        remaining = len(self._rawbuf) - len(cur)
        while remaining > 0:
            dst = self._rawbuf[-remaining:]
            added = self._sock_recv_into(dst)
            if added <= 0:
                assert added == 0
                return (False, cur)
            self._update(0, len(cur) + added)

            cur = self.peek(size)
            index = cur.find(end)
            if index >= 0:
                assert index + len(end) <= size
                return (True, self.peek(index + len(end)))
            if len(cur) >= size:
                assert len(cur) == size
                return (False, self.peek(size))
            remaining = len(self._rawbuf) - len(cur)

        return (False, cur)

    def search(self, size, end, include_end=False, always_return=False):
        assert isinstance(end, bytes)
        if not end:
            raise ValueError('end cannot be empty')
        (found, src) = self.fill_until(size, end)
        if len(src) == 0:
            return src
        if not found:
            if always_return:
                return self.drain(len(src))
            raise ValueError(
                '{!r} not found in {!r}...'.format(end, src[:32])
            )
        ret = self.drain(len(src))
        if include_end:
            return ret
        return ret[0:-len(end)]

    def readline(self, size):
        return self.search(size, b'\n', True, True)

    def read_request(self):
        preamble = self.search(len(self._rawbuf), b'\r\n\r\n')
        if preamble == b'':
            raise EmptyPreambleError('request preamble is empty')
        return parse_request(preamble)

    def read_response(self):
        preamble = self.search(len(self._rawbuf), b'\r\n\r\n')
        if preamble == b'':
            raise EmptyPreambleError('response preamble is empty')
        return parse_response(preamble)

    def read(self, size):
        assert isinstance(size, int)
        if size < 0:
            raise ValueError(
                'need size >= 0; got {}'.format(size)
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
            added = self._sock_recv_into(dst[stop:])
            if added <= 0:
                assert added == 0
                break
            assert stop + added <= size
            stop += added
        return dst[:stop].tobytes()


def format_request_preamble(method, uri, headers):
    lines = ['{} {} HTTP/1.1\r\n'.format(method, uri)]
    if headers:
        header_lines = ['{}: {}\r\n'.format(*kv) for kv in headers.items()]
        header_lines.sort()
        lines.extend(header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode()


def format_response_preamble(status, reason, headers):
    lines = ['HTTP/1.1 {} {}\r\n'.format(status, reason)]
    if headers:
        header_lines = ['{}: {}\r\n'.format(*kv) for kv in headers.items()]
        header_lines.sort()
        lines.extend(header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode()

