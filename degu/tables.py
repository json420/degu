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
Table.
"""

from collections import namedtuple

Entry = namedtuple('Entry', 'i j src dst')


VALID_KEY = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def iter_valid():
    for i in range(256):
        if 32 <= i <= 126:
            c = chr(i)
            if c.isprintable():
                yield Entry(i, i, c, c)
            else:
                yield Entry(i, 255, None, None)
        else:
            yield Entry(i, 255, None, None)


def iter_valid_key():
    for i in range(256):
        if 32 <= i <= 126:
            src = chr(i)
            if src in VALID_KEY:
                dst = src.lower()
                j = ord(dst)
                yield Entry(i, j, src, dst)
            else:
                yield Entry(i, 255, None, None)
        else:
            yield Entry(i, 255, None, None)


def iter_lines(table):
    line = []
    for entry in table:
        s = '{:>3}'.format(entry.j)
        line.append(s)
        if len(line) == 8:
            text = '    {},'.format(', '.join(line))
            yield text
            line = []
    assert not line


def iter_c(name, table):
    yield 'static const Py_UCS1 {}[{:d}] = {{'.format(name, len(table))
    yield from iter_lines(table)
    yield '};'


    
if __name__ == '__main__':
    print('')
    valid = tuple(iter_valid())
    for line in iter_c('VALID', valid):
        print(line)
    print('')

    valid_key = tuple(iter_valid_key())
    for line in iter_c('VALID_KEY', valid_key):
        print(line)
