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
Pure-python fall back implementations for what is in _degu.c.
"""

__all__ = (
    'MAX_LINE_BYTES',
    'MAX_HEADER_COUNT',
    'EmptyPreambleError',
    'read_preamble2',
)

MAX_LINE_BYTES = 4096  # Max length of line in HTTP preamble, including CRLF
MAX_HEADER_COUNT = 15


class EmptyPreambleError(ConnectionError):
    pass


def _readline(rfile_readline, maxsize):
    """
    Matches error checking semantics of READ_LINE() macro in _degu.c.

    As the C implementation of read_preamble() is already over 4x as fast as the
    best optimized pure-Python implementation thus far concocted, it makes sense
    to focus on making the pure-Python implementation a very correct and easy to
    understand reference implementation, even when at the expense of
    performance.

    So although using this _readline() function means a rather hefty performance
    hit for the pure-Python implementation, it helps define the correct behavior
    of the dramatically higher-performance C implementation (aka, the
    implementation you actually want to use).

    But to document the performance impact, when the pure-Python
    implementation of read_preamble() directly calls rfile.readline() with no
    extra error checking::

        131,636: fallback.read_preamble(BytesIO(request_preamble))

    Compared to when the pure-Python implementation of read_preamble() uses this
    _readline() helper function::

         78,342: fallback.read_preamble(BytesIO(request_preamble))

    Compared to the C implementation of read_preamble()::

        536,342: _degu.read_preamble(BytesIO(request_preamble))
    """
    assert isinstance(maxsize, int) and maxsize in (MAX_LINE_BYTES, 2)
    line = rfile_readline(maxsize)
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


def _read_preamble2(rfile):
    rfile_readline = rfile.readline
    if not callable(rfile_readline):
        raise TypeError('rfile.readline is not callable')
    line = _readline(rfile_readline, MAX_LINE_BYTES)
    if not line:
        raise EmptyPreambleError('HTTP preamble is empty')
    if line[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line[-2:]))
    if len(line) == 2:
        raise ValueError('first preamble line is empty')
    first_line = line[:-2].decode('latin_1')
    headers = {}
    for i in range(MAX_HEADER_COUNT):
        line = _readline(rfile_readline, MAX_LINE_BYTES)
        if line[-2:] != b'\r\n':
            raise ValueError(
                'bad header line termination: {!r}'.format(line[-2:])
            )
        if len(line) == 2:  # Stop on the first empty CRLF terminated line
            return (first_line, headers)
        try:
            (key, value) = line[:-2].split(b': ', 1)
        except ValueError:
            key = None
            value = None
        if not (key and value):
            raise ValueError('bad header line: {!r}'.format(line))
        key = key.decode('latin_1').casefold()
        value = value.decode('latin_1')
        if headers.setdefault(key, value) is not value:
            raise ValueError(
                'duplicate header: {!r}'.format(line)
            )
    if _readline(rfile_readline, 2) != b'\r\n':
        raise ValueError('too many headers (> {})'.format(MAX_HEADER_COUNT))
    return (first_line, headers)


def read_preamble2(rfile):
    (first_line, headers) = _read_preamble2(rfile)
    if 'content-length' in headers:
        headers['content-length'] = int(headers['content-length'])
        if headers['content-length'] < 0:
            raise ValueError(
                'negative content-length: {!r}'.format(headers['content-length'])
            ) 
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

