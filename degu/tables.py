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

VALID_KEY = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'


def iter_degu_ascii():
    for i in range(256):
        c = chr(i)
        if 32 <= i <= 126 and c.isprintable():
            yield i
        else:
            yield 255

DEGU_ASCII = tuple(iter_degu_ascii())


def iter_degu_header_key():
    for i in range(256):
        c = chr(i)
        if 32 <= i <= 126 and c in VALID_KEY:
            yield ord(c.lower())
        else:
            yield 255

DEGU_HEADER_KEY = tuple(iter_degu_header_key())


def format_line(line):
    return ' '.join('{:>3}'.format(r) for r in line)


def format_help(help):
    return ''.join(chr(i) for i in help)


def iter_lines(table, comment):
    line = []
    help = []
    for (i, r) in enumerate(table):
        line.append(r)
        if r != 255:
            help.append(i)
        if len(line) == 8:
            text = '    {},'.format(format_line(line))
            if help:
                yield '{}  {} {}'.format(text, comment, format_help(help))
            else:
                yield text
            line = []
            help = []
    assert not line
    assert not help


def iter_c(name, table):
    yield 'static const Py_UCS1 {}[{:d}] = {{'.format(name, len(table))
    yield from iter_lines(table, '//')
    yield '};'


    
if __name__ == '__main__':
    print('')
    for line in iter_c('DEGU_ASCII', DEGU_ASCII):
        print(line)
    print('')

    m = 0
    for line in iter_c('DEGU_HEADER_KEY', DEGU_HEADER_KEY):
        m = max(m, len(line))
        print(line)
    print(m)
