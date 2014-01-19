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
HTTP client.
"""

import socket

from .base import (
    ParseError,
    makefiles,
    read_line,
    read_headers,
    write_chunk,
    Input,
    ChunkedInput,
)


def parse_status(line):
    """
    Parse the status line.

    The return value will be a ``(status, reason)`` tuple, and the status will
    be converted into an integer:

    >>> parse_status('HTTP/1.1 404 Not Found')
    (404, 'Not Found')

    """
    line_parts = line.split(' ', 2)
    if len(line_parts) != 3:
        raise ParseError('Bad Status Line')
    (protocol, status_str, reason) = line_parts

    # Validate protocol:
    if protocol != 'HTTP/1.1':
        raise ParseError('HTTP Version Not Supported')

    # Convent status into an int, validate:
    try:
        status = int(status_str)
    except ValueError:
        raise ParseError('Bad Status Code')
    if not (100 <= status <= 599):
        raise ParseError('Invalid Status Code')

    # Validate reason:
    if not reason:
        raise ParseError('Empty Reason')
    if reason.strip() != reason:
        raise ParseError('Extraneous Whitespace In Reason')

    # Return only (status, reason) as protocol isn't interesting:
    return (status, reason)
