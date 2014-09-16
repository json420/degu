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

Note that the Python implementation is quite different in how it decodes and
validates the HTTP preamble.  Using a lookup table is very fast in C, but is
quite slow in Python.

For *VALUES*, the Python implementation:

    1. Uses ``bytes.decode('ascii')`` to prevent bytes whose high-bit is set

    2. Uses ``str.isprintable()`` to further restrict down to the same 95 byte
       values allowed by the C ``_VALUES`` table

For *KEYS*, the Python implementation:

    1. Uses ``bytes.decode('ascii')`` to prevent bytes whose high-bit is set

    2. Uses ``str.lower()`` to case-fold the header key

    3. Uses ``re.match()`` to further restrict down to the same 63 byte values
       allowed by the C ``_KEYS`` table

Although it might seem a bit hodge-podge, this approach is much faster than
doing lookup tables in pure-Python.

However, aside from the glaring performance difference, the Python and C
implementations should always behave *exactly* the same, and we have oodles of
unit tests to back this up.

By not using lookup tables in the Python implementation, we can better verify
the correctness of the C lookup tables.  Otherwise we could have two
implementations correctly using the same incorrect tables.

``str.isprintable()`` is an especially handy gem in this respect.
"""

import re

__all__ = (
    'MAX_LINE_BYTES',
    'MAX_HEADER_COUNT',
    'EmptyPreambleError',
    'read_preamble',
)

MAX_LINE_BYTES = 4096  # Max length of line in HTTP preamble, including CRLF
MAX_HEADER_COUNT = 15

_RE_KEYS = re.compile('^[-1-9a-z]+$')


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


def _decode_key(src, message):
    """
    Used to decode, validate, and case-fold header keys.
    """
    text = None
    try:
        text = src.decode('ascii').lower()
    except ValueError:
        pass
    if text is None or not _RE_KEYS.match(text):
        raise ValueError(message.format(src))
    return text


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
    assert isinstance(maxsize, int) and maxsize in (MAX_LINE_BYTES, 2)
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


def _read_preamble(rfile):
    readline = rfile.readline
    if not callable(readline):
        raise TypeError('rfile.readline is not callable')
    line = _READLINE(readline, MAX_LINE_BYTES)
    if not line:
        raise EmptyPreambleError('HTTP preamble is empty')
    if line[-2:] != b'\r\n':
        raise ValueError('bad line termination: {!r}'.format(line[-2:]))
    if len(line) == 2:
        raise ValueError('first preamble line is empty')
    first_line = _decode_value(line[:-2], 'bad bytes in first line: {!r}')
    headers = {}
    for i in range(MAX_HEADER_COUNT):
        line = _READLINE(readline, MAX_LINE_BYTES)
        if line[-2:] != b'\r\n':
            raise ValueError(
                'bad header line termination: {!r}'.format(line[-2:])
            )
        if len(line) == 2:  # Stop on the first empty CRLF terminated line
            return (first_line, headers)
        if len(line) < 6:
            raise ValueError('header line too short: {!r}'.format(line))
        try:
            (key, value) = line[:-2].split(b': ', 1)
        except ValueError:
            key = None
            value = None
        if not (key and value):
            raise ValueError('bad header line: {!r}'.format(line))
        key = _decode_key(key, 'bad bytes in header name: {!r}')
        value = _decode_value(value, 'bad bytes in header value: {!r}')
        if headers.setdefault(key, value) is not value:
            raise ValueError(
                'duplicate header: {!r}'.format(line)
            )
    if _READLINE(readline, 2) != b'\r\n':
        raise ValueError('too many headers (> {})'.format(MAX_HEADER_COUNT))
    return (first_line, headers)


def read_preamble(rfile):
    (first_line, headers) = _read_preamble(rfile)
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
