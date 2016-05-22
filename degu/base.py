# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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

try:
    from ._base import (
        EmptyPreambleError,
        API,      APIType,
        Response, ResponseType,
        Range,
        ContentRange,
        Request,
        api,
        Connection,
        Session,
        _handle_requests,
    )
except ImportError:
    from ._basepy import (
        EmptyPreambleError,
        API,      APIType,
        Response, ResponseType,
        Range,
        ContentRange,
        Request,
        api,
        Connection,
        Session,
        _handle_requests,
    )


# FIXME: for compatibility with Degu < 0.16:
bodies = api


__all__ = (
    'EmptyPreambleError',
    'API', 'APIType',
    'Response', 'ResponseType',
    'Range',
    'ContentRange',
    'Request',
    'api',
    'Connection',
    'Session',
    '_handle_requests',
)

# Provide very clear TypeError messages:
_TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

