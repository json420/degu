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
Common HTTP parser used by server and client.
"""

MAX_LINE_BYTES = 4096
MAX_HEADER_COUNT = 10


class ParseError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def read_line(fp):
    # BufferedReader.readline() will stop at the first \n, so there is no reason
    # for us the check the length of the line, just the line termination
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
        raise ParseError('Not Enough Chunk Data Provided')
    if chunk[-2:] != b'\r\n':
        raise ParseError('Bad Chunk Termination')
    return chunk[:-2]


def write_chunk(fp, chunk):
    size_line = '{:x}\r\n'.format(len(chunk))
    fp.write(size_line.encode('latin_1'))
    fp.write(chunk)
    fp.write(b'\r\n')


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
    degu.parser.ParseError: Bad Transfer-Encoding

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


class Output:
    pass


class ChunkedOutput:
    pass


class FileOutput:
    pass


class Input:
    pass


class ChunkedInput:
    pass

