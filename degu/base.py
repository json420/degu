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

from collections import namedtuple
try:
    from ._base import (
        _MAX_LINE_SIZE,
        _MAX_HEADER_COUNT,
        EmptyPreambleError,
        _read_response_preamble,
        _read_request_preamble,
        format_request_preamble,
        format_response_preamble,
        Reader,
    )
except ImportError:
    from ._basepy import (
        _MAX_LINE_SIZE,
        _MAX_HEADER_COUNT,
        EmptyPreambleError,
        _read_request_preamble,
        _read_response_preamble,
        format_request_preamble,
        format_response_preamble,
    )


__all__ = (
    '_MAX_LINE_SIZE',
    '_MAX_HEADER_COUNT',
    'EmptyPreambleError',
    '_read_response_preamble',
    '_read_request_preamble',
    'format_request_preamble',
    'format_response_preamble',
)


MAX_READ_SIZE = 16777216  # 16 MiB
MAX_CHUNK_SIZE = 16777216  # 16 MiB
STREAM_BUFFER_SIZE = 65536  # 64 KiB
IO_SIZE = 1048576  # 1 MiB

# Provide very clear TypeError messages:
_TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


def _makefiles(sock):
    """
    Create (rfile, wfile) from a socket connection.
    """
    return (
        #Reader(sock, bodies),
        sock.makefile('rb', buffering=STREAM_BUFFER_SIZE),
        sock.makefile('wb', buffering=STREAM_BUFFER_SIZE)
    )


# FIXME: Add optional max_size=None keyword argument
def read_chunk(rfile):
    """
    Read a chunk from a chunk-encoded request or response body.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
    """
    line = rfile.readline(_MAX_LINE_SIZE)
    if line[-2:] != b'\r\n':
        raise ValueError('bad chunk size termination: {!r}'.format(line[-2:]))
    parts = line[:-2].split(b';')
    if len(parts) > 2:
        raise ValueError('bad chunk size line: {!r}'.format(line))
    size = int(parts[0], 16)
    if not (0 <= size <= MAX_CHUNK_SIZE):
        raise ValueError(
            'need 0 <= chunk_size <= {}; got {}'.format(MAX_CHUNK_SIZE, size)
        )
    if len(parts) == 2:
        text = None
        try:
            text = parts[1].decode('ascii')  # Disallow the high-bit
        except ValueError:
            pass
        if text is None or not text.isprintable():
            raise ValueError(
                'bad bytes in chunk extension: {!r}'.format(parts[1])
            )
        (key, value) = text.split('=')
        extension = (key, value)
    else:
        extension = None
    data = rfile.read(size)
    if len(data) != size:
        raise ValueError('underflow: {} < {}'.format(len(data), size))
    crlf = rfile.read(2)
    if crlf != b'\r\n':
        raise ValueError('bad chunk data termination: {!r}'.format(crlf))
    return (extension, data)


def _encode_chunk(chunk, check_size=True):
    """
    Internal API for unit testing.
    """
    assert isinstance(chunk, tuple)
    (extension, data) = chunk
    assert extension is None or isinstance(extension, tuple)
    assert isinstance(data, bytes)
    if check_size and len(data) > MAX_CHUNK_SIZE:
        raise ValueError(
            'need len(data) <= {}; got {}'.format(MAX_CHUNK_SIZE, len(data))
        )
    if extension is None:
        size_line = '{:x}\r\n'.format(len(data))
    else:
        (key, value) = extension
        assert isinstance(key, str)
        assert isinstance(value, str)
        size_line = '{:x};{}={}\r\n'.format(len(data), key, value)
    return b''.join([size_line.encode(), data, b'\r\n'])


def write_chunk(wfile, chunk, max_size=None):
    """
    Write *chunk* to *wfile* using chunked transfer-encoding.

    Warning: the optional *max_size* keyword argument isn't yet part of the
    stable API, might go away or change in behavior.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
    """
    assert isinstance(chunk, tuple)
    (extension, data) = chunk
    assert extension is None or isinstance(extension, tuple)
    assert isinstance(data, bytes)
    if max_size is None:
        max_size = MAX_CHUNK_SIZE
    if len(data) > max_size:
        raise ValueError(
            'need len(data) <= {}; got {}'.format(max_size, len(data))
        )
    if extension is None:
        size_line = '{:x}\r\n'.format(len(data))
    else:
        (key, value) = extension
        assert isinstance(key, str)
        assert isinstance(value, str)
        size_line = '{:x};{}={}\r\n'.format(len(data), key, value)
    total = wfile.write(b''.join([size_line.encode(), data, b'\r\n']))
    # Flush buffer as it could be some time before the next chunk is available:
    wfile.flush()
    return total


class Body:
    chunked = False
    __slots__ = ('rfile', 'content_length', 'io_size', 'closed', '_remaining')

    def __init__(self, rfile, content_length, io_size=None):
        if not isinstance(content_length, int):
            raise TypeError(_TYPE_ERROR.format(
                'content_length', int, type(content_length), content_length)
            )
        if content_length < 0:
            raise ValueError(
                'content_length must be >= 0, got: {!r}'.format(content_length)
            )
        if io_size is None:
            io_size = IO_SIZE
        else:
            if not isinstance(io_size, int):
                raise TypeError(
                    _TYPE_ERROR.format('io_size', int, type(io_size), io_size)
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

    def __len__(self):
        return self.content_length

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
        else:
            if not isinstance(size, int):
                raise TypeError(
                    _TYPE_ERROR.format('size', int, type(size), size) 
                )
            if size < 0:
                raise ValueError('size must be >= 0; got {!r}'.format(size))
            read = min(self._remaining, size)
        if read > MAX_READ_SIZE:
            raise ValueError(
                'max read size exceeded: {} > {}'.format(read, MAX_READ_SIZE)
            )
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


class ChunkedBody:
    chunked = True
    __slots__ = ('rfile', 'closed')

    def __init__(self, rfile):
        if not callable(rfile.read):
            raise TypeError('rfile.read is not callable: {!r}'.format(rfile))
        self.rfile = rfile
        self.closed = False

    def __repr__(self):
        return '{}(<rfile>)'.format(self.__class__.__name__)

    def __iter__(self):
        if self.closed:
            raise ValueError('ChunkedBody.closed, already consumed')
        while not self.closed:
            yield self.readchunk()

    # FIXME: Add optional max_size=None keyword argument
    def readchunk(self):
        if self.closed:
            raise ValueError('ChunkedBody.closed, already consumed')
        try:
            (extension, data) = read_chunk(self.rfile)
        except:
            self.rfile.close()
            raise
        if not data:
            self.closed = True
        return (extension, data)

    # FIXME: Add optional size=None, max_size=None keyword arguments
    def read(self, size=None):
        if self.closed:
            raise ValueError('ChunkedBody.closed, already consumed')
        buf = bytearray()
        while not self.closed:
            buf.extend(self.readchunk()[1])
            if len(buf) > MAX_READ_SIZE:
                raise ValueError(
                    'max read size exceeded: {} > {}'.format(
                        len(buf), MAX_READ_SIZE
                    )
                )
        return bytes(buf)

    def write_to(self, wfile):
        wfile.flush()  # Flush preamble before writting first chunk
        return sum(write_chunk(wfile, chunk) for chunk in self) 


class BodyIter:
    chunked = False
    __slots__ = ('source', 'content_length', 'closed', '_started')

    def __init__(self, source, content_length):
        if not isinstance(content_length, int):
            raise TypeError(_TYPE_ERROR.format(
                'content_length', int, type(content_length), content_length)
            )
        if content_length < 0:
            raise ValueError(
                'content_length must be >= 0, got: {!r}'.format(content_length)
            )
        self.source = source
        self.content_length = content_length
        self.closed = False
        self._started = False

    def __len__(self):
        return self.content_length

    def write_to(self, wfile):
        if self.closed:
            raise ValueError('BodyIter.closed, already consumed')
        if self._started:
            raise ValueError('BodyIter._started')
        self._started = True
        content_length = self.content_length
        total = 0
        for data in self.source:
            total += len(data)
            if total > content_length:
                raise ValueError(
                    'overflow: {} > {}'.format(total, content_length)
                )
            if wfile.write(data) != len(data):
                raise Exception('wfile.write() returned wrong size written')
        if total != content_length:
            raise ValueError(
                'underflow: {} < {}'.format(total, content_length)
            )
        wfile.flush()
        self.closed = True
        return total


class ChunkedBodyIter:
    chunked = True
    __slots__ = ('source', 'closed', '_started')

    def __init__(self, source):
        self.source = source
        self.closed = False
        self._started = False

    def write_to(self, wfile):
        if self.closed:
            raise ValueError('ChunkedBodyIter.closed, already consumed')
        if self._started:
            raise ValueError('ChunkedBodyIter._started')
        self._started = True
        wfile.flush()  # Flush preamble before writting first chunk
        empty = False
        total = 0
        for chunk in self.source:
            if empty:
                raise ValueError('non-empty chunk data after empty')
            total += write_chunk(wfile, chunk)
            if not chunk[1]:  # Is chunk data empty?
                empty = True
        if not empty:
            raise ValueError('final chunk data was not empty')
        self.closed = True
        return total


# Used to expose the RGI IO wrappers:
BodiesAPI = namedtuple('BodiesAPI', 'Body BodyIter ChunkedBody ChunkedBodyIter')
bodies = BodiesAPI(Body, BodyIter, ChunkedBody, ChunkedBodyIter)
