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
Common HTTP parser used by server and client, plus a few other bits.
"""

import io

MAX_LINE_BYTES = 4096
MAX_HEADER_COUNT = 10
STREAM_BUFFER_BYTES = 65536  # 64 KiB
FILE_BUFFER_BYTES = 1048576  # 1 MiB


class ParseError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class UnderFlowError(Exception):
    def __init__(self, received, expected):
        self.received = received
        self.expected = expected
        super().__init__(
            'received {:d} bytes, expected {:d}'.format(received, expected)
        )


class OverFlowError(Exception):
    def __init__(self, received, expected):
        self.received = received
        self.expected = expected
        super().__init__(
            'received {:d} bytes, expected {:d}'.format(received, expected)
        )


class ChunkError(Exception):
    pass


class BodyClosedError(Exception):
    """
    Raised when trying to iterate through a closed request or response body.
    """
    def __init__(self, body):
        self.body = body
        super().__init__('cannot iterate, {!r} is closed'.format(body))


def read_line(fp):
    """
    Read a single CRLF terminated line from io.BufferedReader *fp*.

    The return value will be an ``str`` with the decoded latin_1 text, minus the
    terminating CRLF. 
    """
    line_bytes = fp.readline(MAX_LINE_BYTES)
    if line_bytes[-2:] != b'\r\n':
        raise ParseError('Bad Line Termination')
    return line_bytes[:-2].decode('latin_1')


def read_chunk(fp):
    line = read_line(fp)
    try:
        size = int(line.split(';', 1)[0], 16)
    except ValueError:
        raise ParseError('Bad Chunk Size')
    if size < 0:
        raise ParseError('Negative Chunk Size')
    chunk = fp.read(size + 2)
    if len(chunk) != size + 2:
        raise UnderFlowError(len(chunk), size + 2)
    if chunk[-2:] != b'\r\n':
        raise ParseError('Bad Chunk Termination')
    return chunk[:-2]


def write_chunk(fp, chunk):
    size_line = '{:x}\r\n'.format(len(chunk))
    fp.write(size_line.encode('latin_1'))
    fp.write(chunk)
    fp.write(b'\r\n')
    # Flush buffer as it could be some time before the next chunk is available:
    fp.flush()


def parse_header(line):
    """
    Parse a header line.

    The return value will be a ``(key, value)`` tuple, and the key will be
    casefolded.  For example:

    >>> parse_header('Content-Type: application/json')
    ('content-type', 'application/json')

    If parsing a Content-Length header, its value will be parsed into an ``int``
    and validated:

    >>> parse_header('Content-Length: 1776')
    ('content-length', 1776)

    If parsing a Transfer-Encoding header, this functions will raise a
    `ParseError` if the value is anything other than ``'chunked'``.

    >>> parse_header('Transfer-Encoding: clumped')
    Traceback (most recent call last):
      ...
    degu.base.ParseError: Bad Transfer-Encoding

    """
    header_parts = line.split(': ', 1)
    if len(header_parts) != 2:
        raise ParseError('Bad Header Line')
    key = header_parts[0].casefold()
    if key == 'content-length':
        try:
            value = int(header_parts[1])
        except ValueError:
            raise ParseError('Bad Content-Length')
        if value < 0:
            raise ParseError('Negative Content-Length')
    else:
        value = header_parts[1]
        if key == 'transfer-encoding' and value != 'chunked':
            raise ParseError('Bad Transfer-Encoding')
    return (key, value)


def read_headers(fp):
    headers = {}
    for i in range(MAX_HEADER_COUNT + 1):
        line = read_line(fp)
        if line == '':
            if {'content-length', 'transfer-encoding'}.issubset(headers):
                raise ParseError('Content-Length With Transfer-Encoding')
            return headers
        (key, value) = parse_header(line)
        if key in headers:
            raise ParseError('Duplicate Header')
        headers[key] = value
    raise ParseError('Too Many Headers')


def makefiles(sock):
    return (
        sock.makefile('rb', buffering=BUFFER_SIZE_BYTES),
        sock.makefile('wb', buffering=BUFFER_SIZE_BYTES)
    )     


class Output:
    """
    Written to the wfile.

    Content-Length must be known in advance.  On the server side it is used as
    as a response body, and on the client side it is used as a request body.

    >>> body = Output([b'stuff', b'junk'], 9)
    >>> list(body)
    [b'stuff', b'junk']

    """

    __slots__ = ('closed', 'source', 'content_length')

    def __init__(self, source, content_length):
        if not isinstance(content_length, int):
            raise TypeError('content_length must be an int')
        if content_length < 0:
            raise ValueError('content_length must be >= 0')
        self.closed = False
        self.source = source
        self.content_length = content_length

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        received = 0
        for buf in self.source:
            if not isinstance(buf, (bytes, bytearray)):
                self.closed = True
                raise TypeError('buf must be bytes or bytearray')
            received += len(buf)
            if received > self.content_length:
                self.closed = True
                raise OverFlowError(received, self.content_length)
            yield buf
        self.closed = True
        if received != self.content_length:
            raise UnderFlowError(received, self.content_length)


class ChunkedOutput:
    """
    Written to the wfile using chunked encoding.

    For example:

    >>> body = ChunkedOutput([b'stuff', b'junk', b''])
    >>> list(body)
    [b'stuff', b'junk', b'']

    """

    __slots__ = ('closed', 'source',)

    def __init__(self, source):
        self.closed = False
        self.source = source

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        for chunk in self.source:
            if not isinstance(chunk, (bytes, bytearray)):
                self.closed = True
                raise TypeError('chunk must be bytes or bytearray')
            if self.closed:
                raise ChunkError('received non-empty chunk after empty chunk')
            if chunk == b'':
                self.closed = True
            yield chunk
        if not self.closed:
            self.closed = True
            raise ChunkError('final chunk was not empty')


class FileOutput:
    """
    Written to the wfile by reading from an io.BufferedReader.
    """

    __slots__ = ('closed', 'fp', 'content_length')

    def __init__(self, fp, content_length):
        if not isinstance(fp, io.BufferedReader):
            raise TypeError('fp must be an io.BufferedReader')
        if fp.closed:
            raise ValueError('fp is already closed')
        if not isinstance(content_length, int):
            raise TypeError('content_length must be an int')
        if content_length < 0:
            raise ValueError('content_length must be >= 0')
        self.closed = False
        self.fp = fp
        self.content_length = content_length

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        remaining = self.content_length
        while remaining:
            size = min(remaining, FILE_BUFFER_BYTES)
            buf = self.fp.read(size)
            if len(buf) < size:
                self.closed = True
                self.fp.close()
                raise UnderFlowError(len(buf), size)
            remaining -= size
            yield buf
        assert remaining == 0
        self.closed = True
        self.fp.close()



class Input:
    pass


class ChunkedInput:
    pass

