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
Common HTTP parser and IO abstractions used by server and client.
"""

import io


MAX_LINE_BYTES = 4096
MAX_HEADER_COUNT = 10
STREAM_BUFFER_BYTES = 65536  # 64 KiB
FILE_BUFFER_BYTES = 1048576  # 1 MiB

# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


class EmptyPreambleError(ConnectionError):
    pass


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


def read_preamble(rfile):
    """
    Read the HTTP request or response preamble, do low-level parsing.

    The return value will be a ``(first_line, header_lines)`` tuple.

    Over time, there is a good chance that parts of Degu will be replaced with
    high-performance C extensions... and this function is a good candidate.
    """
    line = rfile.readline(MAX_LINE_BYTES)
    if not line:
        raise EmptyPreambleError()
    if line[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line[-2:]))
    if len(line) == 2:
        raise ValueError('first preamble line is empty')
    first_line = line[:-2].decode('latin_1')
    header_lines = []
    for i in range(MAX_HEADER_COUNT):
        line = rfile.readline(MAX_LINE_BYTES)
        if line[-2:] != b'\r\n':
            raise ValueError(
                'bad header line termination: {!r}'.format(line[-2:])
            )
        if len(line) == 2:  # Stop on the first empty CRLF terminated line
            return (first_line, header_lines)
        header_lines.append(line[:-2].decode('latin_1'))
    if rfile.read(2) != b'\r\n':
        raise ValueError('too many headers (> {})'.format(MAX_HEADER_COUNT))
    return (first_line, header_lines)


def read_chunk(rfile):
    """
    Read a chunk from a chunk-encoded request or response body.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1

    Note this function currently ignores any chunk-extension that may be
    present. 
    """
    line = rfile.readline(MAX_LINE_BYTES)
    if line[-2:] != b'\r\n':
        raise ValueError('bad chunk size termination: {!r}'.format(line[-2:]))
    size = int(line[:-2].split(b';')[0], 16)
    if size < 0:
        raise ValueError('negative chunk size: {}'.format(size))
    chunk = rfile.read(size)
    if len(chunk) != size:
        raise UnderFlowError(len(chunk), size)
    crlf = rfile.read(2)
    if crlf != b'\r\n':
        raise ValueError('bad chunk data termination: {!r}'.format(crlf))
    return chunk


def write_chunk(wfile, chunk):
    """
    Write a chunk to a chunk-encoded request or response body.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1

    Note this function currently doesn't support chunk-extensions.
    """
    size_line = '{:x}\r\n'.format(len(chunk))
    total = wfile.write(size_line.encode())
    total += wfile.write(chunk)
    total += wfile.write(b'\r\n')
    # Flush buffer as it could be some time before the next chunk is available:
    # wfile.flush()
    return total


def parse_headers(header_lines):
    """
    Parse *header_lines* into a dictionary with case-folded (lowercase) keys.

    The return value will be a ``dict`` mapping header names to header values,
    and the header names will be case-folded (lowercase).  For example:

    >>> parse_headers(['Content-Type: application/json'])
    {'content-type': 'application/json'}

    """
    headers = {}
    for line in header_lines:
        (key, value) = line.split(': ')
        key = key.casefold()
        if key in headers:
            raise ValueError('duplicate header: {!r}'.format(key))
        headers[key] = value
    if 'content-length' in headers:
        headers['content-length'] = int(headers['content-length'])
        if headers['content-length'] < 0:
            raise ValueError(
                'negative content-length: {!r}'.format(headers['content-length'])
            ) 
        if 'transfer-encoding' in headers:
            raise ValueError(
                "cannot have both 'content-length' and 'transfer-encoding' headers"
            ) 
    elif 'transfer-encoding' in headers:
        if headers['transfer-encoding'] != 'chunked':
            raise ValueError(
                'bad transfer-encoding: {!r}'.format(headers['transfer-encoding'])
            )
    return headers


def makefiles(sock):
    return (
        sock.makefile('rb', buffering=STREAM_BUFFER_BYTES),
        sock.makefile('wb', buffering=STREAM_BUFFER_BYTES)
    )


def make_output_from_input(input_body):
    if isinstance(input_body, Input):
        return Output(input_body, input_body.content_length)
    if isinstance(input_body, ChunkedInput):
        return ChunkedOutput(input_body)
    if input_body is not None:
        raise TypeError('bad input_body: {!r}'.format(type(input_body)))


def build_uri(path_list, query):
    """
    Reconstruct a URI from a parsed path_list and query.

    For example, when there is no query:

    >>> build_uri(['foo', 'bar'], '')
    '/foo/bar'

    And when there is a query:

    >>> build_uri(['foo', 'bar'], 'stuff=junk')
    '/foo/bar?stuff=junk'

    """
    path_str = '/' + '/'.join(path_list)
    if query:
        return '?'.join((path_str, query))
    return path_str  


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
    """
    Read from the rfile.

    Content-Length must be known in advance.
    """

    __slots__ = ('closed', 'rfile', 'content_length', 'remaining')

    def __init__(self, rfile, content_length):
        if not isinstance(rfile, io.BufferedReader):
            raise TypeError('rfile must be an io.BufferedReader')
        if rfile.closed:
            raise ValueError('rfile is already closed')
        if not isinstance(content_length, int):
            raise TypeError('content_length must be an int')
        if content_length < 0:
            raise ValueError('content_length must be >= 0')
        self.closed = False
        self.rfile = rfile
        self.content_length = content_length
        self.remaining = content_length

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.rfile, self.content_length
        )

    def read(self, size=None):
        if size is not None:
            if not isinstance(size, int):
                raise TypeError('size must be an int')
            if size < 0:
                raise ValueError('size must be >= 0')
        if self.closed:
            return b''
        size = (self.remaining if size is None else min(self.remaining, size))
        buf = self.rfile.read(size)
        if len(buf) != size:
            self.closed = True
            raise UnderFlowError(len(buf), size)
        self.remaining -= size
        if self.remaining == 0:
            self.closed = True
        return buf

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        while True:
            buf = self.read(FILE_BUFFER_BYTES)
            if not buf:
                self.closed = True
                break
            yield buf
        assert self.closed is True


class ChunkedInput:
    __slots__ = ('rfile', 'closed')

    def __init__(self, rfile):
        if not isinstance(rfile, io.BufferedReader):
            raise TypeError('rfile must be an io.BufferedReader')
        if rfile.closed:
            raise ValueError('rfile is already closed')
        self.closed = False
        self.rfile = rfile

    def read(self):
        if self.closed:
            return b''
        buf = bytearray()
        while True:
            chunk = self.readchunk()
            if not chunk:
                break
            buf.extend(chunk)
        assert self.closed is True
        return buf

    def readchunk(self):
        if self.closed:
            return b''
        chunk = read_chunk(self.rfile)
        if not chunk:
            self.closed = True
        return chunk

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        while True:
            chunk = self.readchunk()
            yield chunk
            if not chunk:
                self.closed = True
                break
        assert self.closed is True

