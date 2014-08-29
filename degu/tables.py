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
Generate tables for validating and case-folding the HTTP preamble.

Print the C tables like this::

    $ python3 -m degu.tables

Or print the Python tables like this::

    $ python3 -m degu.tables -p

"""

KEYS = b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

VALUES = bytes(sorted(KEYS + b' !"#$%&\'()*+,./:;<=>?@[\\]^_`{|}~'))


def iter_definition(allowed, casefold):
    assert isinstance(allowed, bytes)
    assert isinstance(casefold, bool)
    for i in range(256):
        if 32 <= i <= 127 and i in allowed:
            r = (ord(chr(i).lower()) if casefold else i)
            yield (i, r)
        else:
            yield (i, 255)


# These are table "definitions", not the actual tables:
KEYS_DEF = tuple(iter_definition(KEYS, True))
VALUES_DEF = tuple(iter_definition(VALUES, False))


def format_values(line):
    return ','.join('{:>3}'.format(r) for (i, r) in line)


def needs_help(line):
    for (i, r) in line:
        if r != 255:
            return True
    return False


def iter_help(line):
    for (i, r) in line:
        if r == 255:
            yield ' ' * 4  # 4 spaces
        else:
            yield '{!r:<4}'.format(chr(i))


def format_help(line):
    if needs_help(line):
        return ' '.join(iter_help(line))


def iter_lines(definition, comment):
    line = []
    for item in definition:
        line.append(item)
        if len(line) == 8:
            text = '    {},'.format(format_values(line))
            help = format_help(line)
            if help:
                yield '{} {}  {}'.format(text, comment, help.rstrip())
            else:
                yield text
            line = []
    assert not line


def iter_c(name, definition):
    yield 'static const uint8_t {}[{:d}] = {{'.format(name, len(definition))
    yield from iter_lines(definition, '//')
    yield '};'


def iter_p(name, definition):
    yield '{} = ('.format(name)
    yield from iter_lines(definition, '#')
    yield ')'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', default=False,
        help='generate Python tables (instead of C)'
    )
    args = parser.parse_args()
    iter_x = (iter_p if args.p else iter_c)

    print('')
    for line in iter_x('DEGU_VALUES', VALUES_DEF):
        print(line)

    print('')
    for line in iter_x('DEGU_KEYS', KEYS_DEF):
        print(line)

