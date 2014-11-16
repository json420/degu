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
        MAX_LINE_BYTES,
        MAX_HEADER_COUNT,
        EmptyPreambleError,
        read_preamble,
    )
except ImportError:
    from ._basepy import (
        MAX_LINE_BYTES,
        MAX_HEADER_COUNT,
        EmptyPreambleError,
        read_preamble,
    )


__all__ = (
    'MAX_LINE_BYTES',
    'MAX_HEADER_COUNT',
    'EmptyPreambleError',
    'read_preamble',
)


MAX_READ_BYTES = 16777216  # 16 MiB
MAX_CHUNK_BYTES = 16777216  # 16 MiB
STREAM_BUFFER_BYTES = 65536  # 64 KiB
FILE_IO_BYTES = 1048576  # 1 MiB

# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


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
        super().__init__('body already fully read: {!r}'.format(body))


def makefiles(sock):
    """
    Create (rfile, wfile) from a socket connection.
    """
    return (
        sock.makefile('rb', buffering=STREAM_BUFFER_BYTES),
        sock.makefile('wb', buffering=STREAM_BUFFER_BYTES)
    )


def read_chunk(rfile):
    """
    Read a chunk from a chunk-encoded request or response body.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
    """
    line = rfile.readline(MAX_LINE_BYTES)
    if line[-2:] != b'\r\n':
        raise ValueError('bad chunk size termination: {!r}'.format(line[-2:]))
    parts = line[:-2].split(b';')
    if len(parts) > 2:
        raise ValueError('bad chunk size line: {!r}'.format(line))
    size = int(parts[0], 16)
    if not (0 <= size <= MAX_CHUNK_BYTES):
        raise ValueError(
            'need 0 <= chunk_size <= {}; got {}'.format(MAX_CHUNK_BYTES, size)
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
        raise UnderFlowError(len(data), size)
    crlf = rfile.read(2)
    if crlf != b'\r\n':
        raise ValueError('bad chunk data termination: {!r}'.format(crlf))
    return (extension, data)


def write_chunk(wfile, chunk):
    """
    Write *chunk* to *wfile* using chunked transfer-encoding.

    See "Chunked Transfer Coding":

        http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
    """
    assert isinstance(chunk, tuple)
    (extension, data) = chunk
    assert extension is None or isinstance(extension, tuple)
    assert isinstance(data, bytes)
    if len(data) > MAX_CHUNK_BYTES:
        raise ValueError(
            'need len(data) <= {}; got {}'.format(MAX_CHUNK_BYTES, len(data))
        )
    if extension is None:
        size_line = '{:x}\r\n'.format(len(data))
    else:
        (key, value) = extension
        assert isinstance(key, str)
        assert isinstance(value, str)
        size_line = '{:x};{}={}\r\n'.format(len(data), key, value)
    total = wfile.write(size_line.encode('latin_1'))
    total += wfile.write(data)
    total += wfile.write(b'\r\n')
    # Flush buffer as it could be some time before the next chunk is available:
    wfile.flush()
    return total


class _Body:
    def __len__(self):
        return self.content_length

    def write_to(self, wfile):
        write = wfile.write
        total = sum(write(data) for data in self)
        assert total == self.content_length
        wfile.flush()
        return total


class Body(_Body):
    def __init__(self, rfile, content_length, iosize=None):
        if not callable(rfile.read):
            raise TypeError('rfile.read is not callable: {!r}'.format(rfile))
        if not isinstance(content_length, int):
            raise TypeError(TYPE_ERROR.format(
                'content_length', int, type(content_length), content_length)
            )
        if content_length < 0:
            raise ValueError(
                'content_length must be >= 0, got: {!r}'.format(content_length)
            )
        self.chunked = False
        self.closed = False
        self.rfile = rfile
        self.content_length = content_length
        self.remaining = content_length
        self.iosize = (FILE_IO_BYTES if iosize is None else iosize)
        assert isinstance(self.iosize, int)
        assert self.iosize >= 4096 and self.iosize % 4096 == 0

    def __repr__(self):
        return '{}(<rfile>, {!r})'.format(
            self.__class__.__name__, self.content_length
        )

    def read(self, size=None):
        if self.closed:
            raise BodyClosedError(self)
        if self.remaining <= 0:
            self.closed = True
            return b''
        if size is not None:
            if not isinstance(size, int):
                raise TypeError(
                    TYPE_ERROR.format('size', int, type(size), size) 
                )
            if size < 0:
                raise ValueError('size must be >= 0; got {!r}'.format(size))
        read = (self.remaining if size is None else min(self.remaining, size))
        if read > MAX_READ_BYTES:
            raise ValueError(
                'read size > MAX_READ_BYTES: {} > {}'.format(read, MAX_READ_BYTES)
            )
        data = self.rfile.read(read)
        if len(data) != read:
            # Security note: if application-level code is being overly general
            # with their exception handling, they might continue to use a
            # connection even after an UnderFlowError, which could create a
            # request/response stream state inconsistency.  So in this
            # circumstance, we close the rfile, but we do *not* set Body.closed
            # to True (which means "fully consumed") because the body was not in
            # fact fully read. 
            self.rfile.close()
            raise UnderFlowError(len(data), read)
        self.remaining -= read
        assert self.remaining >= 0
        if size is None:
            # Entire body was request at once, so close:
            self.closed = True
        return data

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        remaining = self.remaining
        if remaining != self.content_length:
            raise Exception('cannot mix Body.read() with Body.__iter__()')
        self.remaining = 0
        iosize = self.iosize
        read = self.rfile.read
        while remaining > 0:
            readsize = min(remaining, iosize)
            remaining -= readsize
            assert remaining >= 0
            data = read(readsize)
            if len(data) != readsize:
                self.rfile.close()
                raise UnderFlowError(len(data), readsize)
            yield data
        self.closed = True


class BodyIter(_Body):
    def __init__(self, source, content_length):
        if not isinstance(content_length, int):
            raise TypeError(TYPE_ERROR.format(
                'content_length', int, type(content_length), content_length)
            )
        if content_length < 0:
            raise ValueError(
                'content_length must be >= 0, got: {!r}'.format(content_length)
            )
        self.source = source
        self.content_length = content_length
        self.closed = False

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        self.closed = True
        content_length = self.content_length
        total = 0
        for data in self.source:
            total += len(data)
            if total > content_length:
                raise OverFlowError(total, content_length)
            yield data
        if total != content_length:
            raise UnderFlowError(total, content_length)


class _ChunkedBody:
    def write_to(self, wfile):
        write = wfile.write
        flush = wfile.flush
        flush()  # Flush preamble before writting first chunk
        total = 0
        for (extension, data) in self:
            if extension:
                (key, value) = extension
                size_line = '{:x};{}={}\r\n'.format(len(data), key, value)
            else:
                size_line = '{:x}\r\n'.format(len(data))
            total += write(size_line.encode())
            total += write(data)
            total += write(b'\r\n')
            flush()
        return total


class ChunkedBody(_ChunkedBody):
    def __init__(self, rfile):
        if not callable(rfile.read):
            raise TypeError('rfile.read is not callable: {!r}'.format(rfile))
        self.chunked = True
        self.closed = False
        self.rfile = rfile

    def __repr__(self):
        return '{}(<rfile>)'.format(self.__class__.__name__)

    def readchunk(self):
        if self.closed:
            raise BodyClosedError(self)
        try:
            (extension, data) = read_chunk(self.rfile)
        except:
            self.rfile.close()
            raise
        if not data:
            self.closed = True
        return (extension, data)

    def read(self):
        # FIXME: consider removing this, or at least adding some sane memory
        # usage limit.  For now, kept for transition compatibility with
        # Microfiber:
        if self.closed:
            raise BodyClosedError(self)
        buf = bytearray()
        while not self.closed:
            buf.extend(self.readchunk()[1])
        return bytes(buf)

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        while not self.closed:
            yield self.readchunk()


class ChunkedBodyIter(_ChunkedBody):
    def __init__(self, source):
        self.source = source
        self.closed = False

    def __iter__(self):
        if self.closed:
            raise BodyClosedError(self)
        self.closed = True
        empty = False
        for (extension, data) in self.source:
            if empty:
                raise ChunkError('non-empty chunk data after empty')
            yield (extension, data)
            if not data:
                empty = True
        if not empty:
            raise ChunkError('final chunk data was not empty')


# Used to expose the RGI IO wrappers:
BodiesAPI = namedtuple('BodiesAPI', 'Body BodyIter ChunkedBody ChunkedBodyIter')
bodies = BodiesAPI(Body, BodyIter, ChunkedBody, ChunkedBodyIter)
