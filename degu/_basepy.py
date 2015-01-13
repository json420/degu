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

MAX_PREAMBLE_BYTES = 65536  # 64 KiB

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
    if src[0:1] != b'/':
        raise ValueError("uri[0:1] != b'/': {!r}".format(src))

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


def _READLINE(readline, maxsize):
    """
    Matches error checking semantics of the _READLINE() macro in degu/_base.c.

    It makes sense to focus on making the pure-Python implementation a very
    correct and easy to understand reference implementation, even when at the
    expense of performance.

    So although using this _READLINE() function means a rather hefty performance
    hit for the pure-Python implementation, it helps define the correct behavior
    of the dramatically higher-performance C implementation (aka, the
    implementation you actually want to use).
    """
    assert isinstance(maxsize, int) and maxsize in (_MAX_LINE_SIZE, 2)
    line = readline(maxsize)
    if type(line) is not bytes:
        raise TypeError(
            'rfile.readline() returned {!r}, should return {!r}'.format(
                type(line), bytes
            )
        )
    if len(line) > maxsize:
        raise ValueError(
            'rfile.readline() returned {} bytes, expected at most {}'.format(
                len(line), maxsize
            )
        )
    return line


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
        raise ValueError('bad status in response line: {!r}'.format(line))

    # reason:
    if line[13:] == b'OK':
        reason = OK
    else:
        reason = _decode_value(line[13:], 'bad reason in response line: {!r}')

    # Return (status, reason) 2-tuple:
    return (status, reason)


def parse_request_line(line):
    if isinstance(line, str):
        line = line.encode()
    if len(line) < 14:
        raise ValueError('request line too short: {!r}'.format(line))
    if line[-9:] != b' HTTP/1.1':
        raise ValueError('bad protocol in request line: {!r}'.format(line))
    line = line[:-9]
    items = line.split(b' /', 1)
    if len(items) < 2:
        raise ValueError('bad inner request line: {!r}'.format(line))
    return (
        parse_method(items[0]),
        _decode_uri( b'/' + items[1])
    )


def parse_preamble(preamble):
    (first_line, *header_lines) = preamble.split(b'\r\n')
    first_line = _decode_value(first_line, 'bad bytes in first line: {!r}')
    headers = {}
    for line in header_lines:
        (key, value) = line.split(b': ')
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
                'bad transfer-encoding: {!r}'.format(headers['transfer-encoding'])
            )
    return (first_line, headers)


def __read_headers(readline):
    headers = {}
    for i in range(_MAX_HEADER_COUNT):
        line = _READLINE(readline, _MAX_LINE_SIZE)
        crlf = line[-2:]
        if crlf != b'\r\n':
            raise ValueError('bad header line termination: {!r}'.format(crlf))
        if line == b'\r\n':  # Stop on the first empty CRLF terminated line
            return headers
        if len(line) < 6:
            raise ValueError('header line too short: {!r}'.format(line))
        assert line[-2:] == b'\r\n'
        line = line[:-2]
        try:
            (key, value) = line.split(b': ', 1)
        except ValueError:
            key = None
            value = None
        if not (key and value):
            raise ValueError('bad header line: {!r}'.format(line))
        if key.lower() == b'content-length':
            key = 'content-length'
            value = parse_content_length(value)
        elif key.lower() == b'transfer-encoding':
            if value != b'chunked':
                raise ValueError(
                    'bad transfer-encoding: {!r}'.format(value)
                )
            key = 'transfer-encoding'
            value = 'chunked'
        else:
            key = parse_header_name(key)
            value = _decode_value(value, 'bad bytes in header value: {!r}')
        if headers.setdefault(key, value) is not value:
            raise ValueError(
                'duplicate header: {!r}'.format(line)
            )
    if _READLINE(readline, 2) != b'\r\n':
        raise ValueError('too many headers (> {})'.format(_MAX_HEADER_COUNT))
    return headers


def _read_response_preamble(rfile):
    readline = rfile.readline
    if not callable(readline):
        raise TypeError('rfile.readline is not callable')
    line = _READLINE(readline, _MAX_LINE_SIZE)
    if not line:
        raise EmptyPreambleError('HTTP preamble is empty')
    if line[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line[-2:]))
    if len(line) == 2:
        raise ValueError('first preamble line is empty')
    (status, reason) = parse_response_line(line[:-2])
    headers = __read_headers(readline)
    if 'content-length' in headers and 'transfer-encoding' in headers:
        raise ValueError(
            'cannot have both content-length and transfer-encoding headers'
        )
    return (status, reason, headers)


def _read_request_preamble(rfile):
    readline = rfile.readline
    if not callable(readline):
        raise TypeError('rfile.readline is not callable')
    line = _READLINE(readline, _MAX_LINE_SIZE)
    if not line:
        raise EmptyPreambleError('HTTP preamble is empty')
    if line[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line[-2:]))
    if len(line) == 2:
        raise ValueError('first preamble line is empty')
    (method, uri) = parse_request_line(line[:-2])
    headers = __read_headers(readline)
    if 'content-length' in headers and 'transfer-encoding' in headers:
        raise ValueError(
            'cannot have both content-length and transfer-encoding headers'
        )
    return (method, uri, headers)


class Reader:
    __slots__ = ('sock', 'bodies', '_buf', '_start', '_stop', '_rawtell')

    def __init__(self, sock, bodies):
        self.sock = sock
        self.bodies = bodies
        self._buf = memoryview(bytearray(MAX_PREAMBLE_BYTES))
        self._start = 0
        self._stop = 0
        self._rawtell = 0

    def _check_start_stop(self):
        (start, stop) = (self._start, self._stop)
        assert isinstance(start, int)
        assert isinstance(stop, int)
        assert 0 <= start <= stop <= len(self._buf)
        if stop == 0:
            assert start == 0
        return (start, stop)

    def avail(self):
        (start, stop) = self._check_start_stop()
        avail = stop - start
        assert 0 <= avail <= len(self._buf)
        return avail

    def rawtell(self):
        return self._rawtell

    def tell(self):
        return self._rawtell - self.avail()

    def _fill_buffer(self):
        (start, stop) = self._check_start_stop()
        size = stop - start
        assert 0 <= size <= len(self._buf)

        # Nothing to do if buffer is already full:
        if size == len(self._buf):
            return 0

        # If needed, set buf[0:size] = buf[start:stop]
        if size > 0 and start > 0:
            self._buf[0:size] = self._buf[start:stop]
            self._start = 0
            self._stop = size
            (start, stop) = self._check_start_stop()
            assert start == 0
            assert stop == size

        added = self.sock.recv_into(self._buf[size:])
        self._stop += added
        self._rawtell += added
        self._check_start_stop()
        return added

    def _consume_buffer(self, size):
        avail = self.avail()
        assert 1 <= size <= avail
        if size == avail:
            self._start = 0
            self._stop = 0
        else:
            assert size < avail
            self._start += size
        self._check_start_stop()

    def _get_cur(self, max_size=None):
        (start, stop) = self._check_start_stop()
        avail = stop - start
        size = (avail if max_size is None else min(avail, max_size))
        assert start + size <= stop
        return self._buf[start:start + size]

    def _cur_to_bytes(self, start=0, stop=None):
        if stop is None:
            stop = len(self._buf)
        assert isinstance(start, int)
        assert isinstance(stop, int)
        assert 0 <= start <= stop <= len(self._buf)
        cur = self._get_cur()
        return cur[start:stop].tobytes()

    def _cur_to_bytes2(self, max_size):
        cur = self._get_cur()
        size = min(len(cur), max_size)
        return cur[0:size].tobytes()

    def _read_until(self, term, message, max_size=1024):
        assert isinstance(term, bytes) and len(term) >= 2
        assert isinstance(max_size, int) and 512 <= max_size <= len(self._buf)
        cur = self._cur_to_bytes2(max_size)
        index = cur.find(term)
        if index < 0:
            raise ValueError(message.format(cur[-len(term):]))
        assert 0 <= index <= len(cur) - len(term)
        self._consume_buffer(index + len(term))
        return cur[:index]

    def read_raw_preamble(self):
        self._fill_buffer()
        avail = self.avail()
        if avail == 0:
            raise EmptyPreambleError('HTTP preamble is empty')
        if avail < 4:
            raise ValueError(
                'HTTP preamble too short: {!r}'.format(self._cur_to_bytes())
            )
        return self._read_until(b'\r\n\r\n', 'bad preamble termination: {!r}')

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

