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
RGI validation middleware.
"""


# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'

SESSION_REQUIRED = frozenset([
    'rgi.version',
    'rgi.Body',
    'rgi.BodyIter',
    'rgi.ChunkedBody',
    'rgi.ChunkedBodyIter',
])


def _check_str_keys(name, obj):
    """
    Make sure all keys in *obj* are `str` instances.
    """
    assert isinstance(name, str)
    assert isinstance(obj, dict)
    for key in obj:
        if not isinstance(key, str):
            raise TypeError('{}: keys must be {!r}; got a {!r}: {!r}'.format(
                    name, str, type(key), key
                )
            )


def _check_required_keys(name, obj, required):
    """
    Make sure all required keys are present in *obj*.
    """
    assert isinstance(name, str)
    assert isinstance(obj, dict)
    assert isinstance(required, frozenset)
    for key in required:
        assert isinstance(key, str)
        if key not in obj:
            raise ValueError('{}: missing required key {!r}'.format(name, key))


def _validate_session(session):
    if not isinstance(session, dict):
        raise TypeError(
            TYPE_ERROR.format('session', dict, type(session), session)

        )
    _check_str_keys('session', session)
    _check_required_keys('session', session, SESSION_REQUIRED)

    # rgi.version:
    value = session['rgi.version']
    label = "session['rgi.version']"
    if not isinstance(value, tuple):
        raise TypeError(
            TYPE_ERROR.format(label, tuple, type(value), value) 
        )
    if len(value) != 2:
        raise ValueError(
            'len({}) must be 2; got {}: {!r}'.format(label, len(value), value)
        )
    for i in range(len(value)):
        value = session['rgi.version'][i]
        label = "session['rgi.version'][{!r}]".format(i)
        if not isinstance(value, int):
            raise TypeError(
                TYPE_ERROR.format(label, int, type(value), value) 
            )
        if value < 0:
            raise ValueError('{} must be >= 0; got {!r}'.format(label, value))

    # Make sure Body, BodyIter, ChunkedBody, ChunkedBodyIter are classes:
    keys = (
        'rgi.Body',
        'rgi.BodyIter',
        'rgi.ChunkedBody',
        'rgi.ChunkedBodyIter',
    )
    for key in keys:
        value = session[key]
        label = 'session[{!r}]'.format(key)
        if not issubclass(value, object):
            raise Exception('Internal error, should not be reached')


