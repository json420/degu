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
import ssl
from collections import namedtuple


MAX_LINE_BYTES = 4096
MAX_HEADER_COUNT = 10
STREAM_BUFFER_BYTES = 65536  # 64 KiB
FILE_BUFFER_BYTES = 1048576  # 1 MiB

# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

# Hack so we can unit test Python 3.4 as planned, but still also work with
# Python 3.3 for the time being; note this does not make Degu running under
# Python 3.4 *network* compatible with Degu running under Python 3.3
_TLS = namedtuple('TSL', 'protocol name ciphers')
if hasattr(ssl, 'PROTOCOL_TLSv1_2'):
    TLS = _TLS(ssl.PROTOCOL_TLSv1_2, 'PROTOCOL_TLSv1_2', 'ECDHE-RSA-AES256-GCM-SHA384')
else:
    TLS = _TLS(ssl.PROTOCOL_TLSv1, 'PROTOCOL_TLSv1', 'ECDHE-RSA-AES256-SHA')


class EmptyLineError(ConnectionError):
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


def build_base_sslctx():
    """
    Build an ssl.SSLContext with the shared server and client features.
    """
    sslctx = ssl.SSLContext(TLS.protocol)

    # By setting this to something so restrictive, we make sure that the client
    # wont connect to a server unless it provides perfect forward secrecy:
    #   TLSv1:   ECDHE-RSA-AES256-SHA
    #   TLSv1.2: ECDHE-RSA-AES256-GCM-SHA384
    sslctx.set_ciphers(TLS.ciphers)

    # FIXME: According to the docs, ssl.OP_NO_SSLv2 has no effect on
    # ssl.PROTOCOL_TLSv1; however, the ssl.create_default_context() function in
    # Python 3.4 is still setting this, so we are too:
    sslctx.options |= ssl.OP_NO_SSLv2

    # Protect against CRIME-like attacks, plus better media file transfer rates;
    # note that on Debian/Ubuntu systems, libssl (openssl) is built with TSL
    # compression disabled system-wide, so we can't deep unit test for this
    # using SSLSocket.compression() as that will always return None:
    sslctx.options |= ssl.OP_NO_COMPRESSION
    return sslctx


def validate_sslctx(sslctx):
    if not isinstance(sslctx, ssl.SSLContext):
        raise TypeError('sslctx must be an ssl.SSLContext')
    if sslctx.protocol != TLS.protocol:
        raise ValueError('sslctx.protocol must be ssl.{}'.format(TLS.name))
    if not (sslctx.options & ssl.OP_NO_SSLv2):
        raise ValueError('sslctx.options must include ssl.OP_NO_SSLv2')
    if not (sslctx.options & ssl.OP_NO_COMPRESSION):
        raise ValueError('sslctx.options must include ssl.OP_NO_COMPRESSION')


def read_lines_iter(rfile):
    line_bytes = rfile.readline(MAX_LINE_BYTES)
    if not line_bytes:
        raise EmptyLineError()
    if line_bytes[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line_bytes))
    yield line_bytes[:-2].decode('latin_1')
    for i in range(MAX_HEADER_COUNT + 1):
        line_bytes = rfile.readline(MAX_LINE_BYTES)
        if line_bytes == b'\r\n':
            return
        if line_bytes[-2:] != b'\r\n':
            raise ValueError('bad line termination: {!r}'.format(line_bytes))
        yield line_bytes[:-2].decode('latin_1')
    raise ValueError('too many headers (> {})'.format(MAX_HEADER_COUNT))


def read_chunk(rfile):
    line_bytes = rfile.readline(MAX_LINE_BYTES)
    if line_bytes[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line_bytes))
    size = int(line_bytes.split(b';')[0], 16)
    if size < 0:
        raise ValueError('negative chunk size: {}'.format(size))
    chunk = rfile.read(size + 2)
    if len(chunk) != size + 2:
        raise UnderFlowError(len(chunk), size + 2)
    if chunk[-2:] != b'\r\n':
        raise ValueError('bad chunk termination: {!r}'.format(chunk[-2:]))
    return chunk[:-2]


def write_chunk(wfile, chunk):
    size_line = '{:x}\r\n'.format(len(chunk))
    total = wfile.write(size_line.encode())
    total += wfile.write(chunk)
    total += wfile.write(b'\r\n')
    # Flush buffer as it could be some time before the next chunk is available:
    wfile.flush()
    return total


def parse_headers(lines):
    """
    Parse the header lines.

    The return value will be a ``dict`` mapping header names to header values,
    and the header names will be case-folded.  For example:

    >>> parse_headers(['Content-Type: application/json'])
    {'content-type': 'application/json'}

    Although allowed by HTTP 1.1 (but seldom used in practice), this function
    does not permit multiple occurrences of the same header name:

    >>> parse_headers(['Content-Type: foo/bar', 'Content-Type: stuff/junk'])
    Traceback (most recent call last):
      ...
    ValueError: duplicate header: 'content-type'

    If parsing a Content-Length header, its value will be parsed into an ``int``
    and validated:

    >>> parse_headers(['Content-Length: 1776'])
    {'content-length': 1776}

    If parsing a Transfer-Encoding header, this functions will raise a
    ``ValueError`` if the value is anything other than ``'chunked'``.

    >>> parse_headers(['Transfer-Encoding: clumped'])
    Traceback (most recent call last):
      ...
    ValueError: bad transfer-encoding: 'clumped'

    Finally, this function will likewise raise a ValueError if the header lines
    include both Content-Length and Transfer-Encoding headers:

    >>> parse_headers(['Transfer-Encoding: chunked', 'Content-Length: 1776'])
    Traceback (most recent call last):
      ...
    ValueError: content-length plus transfer-encoding

    """
    headers = {}
    for line in lines:
        (key, value) = line.split(': ')
        key = key.casefold()
        if key in headers:
            raise ValueError('duplicate header: {!r}'.format(key))
        headers[key] = value
    if 'content-length' in headers:
        headers['content-length'] = int(headers['content-length'])
        if headers['content-length'] < 0:
            raise ValueError('negative content-length: {!r}'.format(
                    headers['content-length'])) 
        if 'transfer-encoding' in headers:
            raise ValueError('content-length plus transfer-encoding') 
    elif 'transfer-encoding' in headers:
        if headers['transfer-encoding'] != 'chunked':
            raise ValueError('bad transfer-encoding: {!r}'.format(
                    headers['transfer-encoding']))
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

