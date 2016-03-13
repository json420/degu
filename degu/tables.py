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
Generate tables for validating the HTTP preamble and the HTTP chunk line.

Print the C tables like this::

    $ python3 -m degu.tables

Or print the Python tables like this::

    $ python3 -m degu.tables --python

Finally, replace the existing tables in the "degu/_base.h" and "degu/_basepy.py"
files with the tables as currently defined in this module like this::

    $ python3 -m degu.tables --update

Obviously you should only use --update within the source tree.

If the existing tables already matched the current table definitions, the
content of these files should not change (if it does change, that's a bug).
However, the mtime of these files will change regardless, as a new file is still
written even when the resulting content will be the same. 
"""

from collections import namedtuple
import os
from os import path
import argparse


# Provide very clear TypeError messages:
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


Table = namedtuple('Table', 'name ignore items')
BitFlag = namedtuple('BitFlag', 'bit name allowed')
BitMask = namedtuple('BitMask', 'mask name flags allowed')
Info = namedtuple('Info', 'flags masks table')
Markers = namedtuple('Markers', 'begin end')
Numbers = namedtuple('Numbers', 'decimal hexadecimal')

COOKIE = b' -/0123456789:;=ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'

# For case-folding and validating header names:
NAMES_DEF = b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

# For parsing decimal and hexadecimal values:
DECIMAL_DEF = b'0123456789'
HEXADECIMAL_DEF = DECIMAL_DEF + b'ABCDEFabcdef'
NUM_DEF = Numbers(DECIMAL_DEF, HEXADECIMAL_DEF)

# Generic bit-flag based validation table with 7 sets, plus 1 error set:
BIT_FLAGS_DEF = (
    ('LOWER', b'-0123456789abcdefghijklmnopqrstuvwxyz'),
    ('UPPER', b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    ('URI',   b'/?'),
    ('PATH',  b'+.:_~'),
    ('QUERY', b'%&='),
    ('SPACE', b' '),
    ('VALUE', b'"\'()*,;<>[]'),   
)

# The above can be combined to produce a number of validation masks:
BIT_MASKS_DEF = (
    ('KEY',    ('LOWER',)),
    ('VAL',    ('LOWER', 'UPPER', 'PATH', 'QUERY', 'URI', 'SPACE', 'VALUE')),
    ('URI',    ('LOWER', 'UPPER', 'PATH', 'QUERY', 'URI')),
    ('PATH',   ('LOWER', 'UPPER', 'PATH')),
    ('QUERY',  ('LOWER', 'UPPER', 'PATH', 'QUERY')),
    ('REASON', ('LOWER', 'UPPER', 'SPACE')),
    ('EXTKEY', ('LOWER', 'UPPER')),
    ('EXTVAL', ('LOWER', 'UPPER', 'PATH', 'VALUE')),
)


def _iter_never_allowed():
    for i in range(256):
        if (0 <= i <= 31) or (127 <= i <= 255):
            yield i
        else:
            c = chr(i)
            assert c == bytes([i]).decode('ascii')
            if c.isprintable() is False:
                yield i

NEVER_ALLOWED = bytes(_iter_never_allowed())
NEVER_ALLOWED_SET = frozenset(NEVER_ALLOWED)


def normalize(source):
    return bytes(sorted(set(source)))


def check_allowed(allowed):
    if not isinstance(allowed, bytes):
        raise TypeError(
            TYPE_ERROR.format('allowed', bytes, type(allowed), allowed)
        )
    expected = normalize(allowed)
    if allowed != expected:
        raise ValueError('{!r} != {!r}'.format(allowed, expected))
    if NEVER_ALLOWED_SET.intersection(allowed):
        raise ValueError(
            'contains bytes that are never allowed: {!r}'.format(allowed)
        )
    return allowed


def invert(allowed):
    return normalize(set(range(256)) - set(check_allowed(allowed)))


def check_disjoint(accum, allowed):
    check_allowed(allowed)
    common = set(accum).intersection(allowed)
    if common:
        common = normalize(common)
        accum = normalize(accum)
        raise ValueError(
            '{!r} common between {!r} and {!r}'.format(
                normalize(common), normalize(accum), allowed
            )
        )


def build_names_table(allowed):
    check_allowed(allowed)
    items = []
    for i in range(256):
        if i in allowed:
            r = ord(chr(i).lower())
            pair = (i, r)
        else:
            pair = (i, 255)
        items.append(pair)
    return Table('_NAME', 255, tuple(items))


def build_num_table(num):
    assert type(num) is Numbers
    allowed = num.hexadecimal
    check_allowed(allowed)
    items = []
    for i in range(256):
        if i in allowed:
            r = allowed.index(bytes([i]).upper())
            assert 0 <= r < 16
            if r >= 10:
                r |= 16
            else:
                assert i in num.decimal
            pair = (i, r)
        else:
            pair = (i, 255)
        items.append(pair)
    return Table('_NUMBER', 255, tuple(items))


def build_flags(flags_def):
    assert 0 < len(flags_def) < 8
    accum = []
    for (i, (name, allowed)) in enumerate(flags_def):
        bit = 2 ** i
        assert bit in (1, 2, 4, 8, 16, 32, 64)
        accum.append(BitFlag(bit, name, allowed))
    return tuple(accum)


def build_masks(flags, masks_def):
    accum = []
    _map = dict((f.name, f) for f in flags)
    for (name, parts) in masks_def:
        bits = 0
        union = set()
        for p in parts:
            f = _map[p]
            bits |= f.bit
            check_disjoint(union, f.allowed)
            union.update(f.allowed)
        mask = 255 ^ bits
        allowed = normalize(union)
        assert len(allowed) == len(union)
        accum.append(BitMask(mask, name, parts, allowed))
    return tuple(accum)


def build_flags_table(flags):
    assert 1 < len(flags) < 8
    table = {}
    for f in flags:
        check_allowed(f.allowed)
        assert set(table).isdisjoint(f.allowed)
        table.update((key, f.bit) for key in f.allowed)
    for key in range(256):
        table.setdefault(key, 128)
    assert len(table) == 256
    items = tuple(sorted(table.items()))
    return Table('_FLAG', 128, items)


def build_info(flags_def, masks_def):
    flags = build_flags(flags_def)
    masks = build_masks(flags, masks_def)
    table = build_flags_table(flags)
    return Info(flags, masks, table)


def format_table_row(row):
    return ','.join('{:>3}'.format(r) for (i, r) in row)


def format_table_row_help(row, ignore):
    if set(r for (i, r) in row) == {ignore}:
        return None
    help = []
    for (i, r) in row:
        if r == ignore:
            help.append(' ' * 4)  # 4 spaces
        else:
            help.append('{!r:<4}'.format(chr(i)))
    return ' '.join(help)


def iter_c_table_rows(table):
    assert table.ignore in (255, 128)
    row = []
    for item in table.items:
        row.append(item)
        if len(row) == 8:
            line = '    {},'.format(format_table_row(row))
            help = format_table_row_help(row, table.ignore)
            if help:
                yield '{} //  {}'.format(line, help.rstrip())
            else:
                yield line
            row = []
    assert not row


def iter_c_table(table):
    assert len(table.items) == 256
    yield 'static const uint8_t {}[{:d}] = {{'.format(
        table.name, len(table.items)
    )
    yield from iter_c_table_rows(table)
    yield '};'


def iter_c_bit_flags_comment(flags):
    width = max(len(f.name) for f in flags)
    yield '/*'
    for f in flags:
        name = f.name.ljust(width)
        yield ' * {} {:>2} {:08b}  {!r}'.format(name, f.bit, f.bit, f.allowed)
    yield ' */'


def mask_name(name):
    assert 'mask' not in name.lower()
    assert name.upper() == name
    return name + '_MASK'


def iter_c_bit_masks(masks):
    width = max(len(mask_name(m.name)) for m in masks)
    for m in masks:
        name = mask_name(m.name).ljust(width)
        assert m.flags is not None
        parts = '~({})'.format('|'.join(m.flags))
        yield '#define {} {:>3}  // {:08b} {}'.format(
            name, m.mask, m.mask, parts
        )


def iter_c_info(info):
    yield from iter_c_bit_flags_comment(info.flags)
    yield from iter_c_bit_masks(info.masks)
    yield from iter_c_table(info.table)


def py_flag_name(name):
    return '_{}'.format(name)


def iter_py_info(info):
    width = max(len(py_flag_name(f.name)) for f in info.flags)
    for f in info.flags:
        name = py_flag_name(f.name).ljust(width)
        yield '{} = {!r}'.format(name, f.allowed)
    yield ''
    width = max(len(m.name) for m in info.masks)
    for m in info.masks:
        name = m.name.ljust(width)
        src = ' + '.join(py_flag_name(n) for n in m.flags)
        yield '{} = frozenset({})'.format(name, src)


def build_marker_comments(end, fill):
    labels = tuple(
        '{} GENERATED TABLES'.format(way) for way in ('BEGIN', 'END')
    )
    width = max(len(l) for l in labels)
    markers = []
    for label in labels:
        line = ''.join([
            end,
            (fill * 15),
            (' ' * 4),
            label.ljust(width),
            (' ' * 4),
        ])
        needfill = 80 - len(line) - 1
        line += (fill * needfill) + end
        markers.append(line)
    return Markers(*markers)


def replace(inlines, markers, newlines):
    # States:
    #   0: start marker not yet found
    #   1: start marker found, end marker not yet found
    #   2: end marker found (no markers should be found again)
    state = 0
    outlines = []
    for line in inlines:
        assert state in (0, 1, 2)
        if line == markers.begin:
            assert state == 0
            state += 1
        if state in (0, 2):
            outlines.append(line)
        if line == markers.end:
            assert state == 1
            state += 1
            for new in newlines:
                outlines.append(new)
    assert state == 2
    return outlines


def update(pkgdir, name, markers, newlines):
    orig = path.join(pkgdir, name)
    tmp = orig + '.updated-tables.new'
    bak = orig + '.updated-tables.old'
    text = open(orig, 'r').read()
    inlines = text.splitlines()
    outlines = replace(inlines, markers, newlines)
    with open(tmp, 'x') as fp:
        fp.write('\n'.join(outlines) + '\n')
    os.rename(orig, bak)
    os.rename(tmp, orig)
    print('Updated {!r}'.format(orig))


class Generated:
    def __init__(self, names_def, flags_def, masks_def, num_def):
        self.names_def = names_def
        self.names_table = build_names_table(names_def)
        self.info = build_info(flags_def, masks_def)
        self.markers_c = build_marker_comments('/', '*')
        self.markers_py = build_marker_comments('#', '#')
        self.num_def = num_def
        self.num_table = build_num_table(num_def)

    def iter_lines_c(self):
        yield self.markers_c.begin
        yield from iter_c_table(self.names_table)
        yield ''
        yield from iter_c_table(self.num_table)
        yield ''
        yield from iter_c_info(self.info)
        yield self.markers_c.end

    def iter_lines_py(self):
        yield self.markers_py.begin
        yield 'NAME = frozenset('
        yield '    {!r}'.format(self.names_def)
        yield ')'
        yield ''
        yield 'DECIMAL = frozenset({!r})'.format(self.num_def.decimal)
        yield 'HEXADECIMAL = frozenset({!r})'.format(self.num_def.hexadecimal)
        yield ''
        yield from iter_py_info(self.info)
        yield self.markers_py.end

    def update(self, pkgdir):
        update(pkgdir, '_base.h', self.markers_c, self.iter_lines_c())
        update(pkgdir, '_basepy.py', self.markers_py, self.iter_lines_py())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--python', action='store_true', default=False,
        help='print Python tables (instead of C)'
    )
    parser.add_argument('--update', action='store_true', default=False,
        help="update tables in 'degu/_base.c', 'degu/_basepy.py'"
    )
    args = parser.parse_args()

    gen = Generated(NAMES_DEF, BIT_FLAGS_DEF, BIT_MASKS_DEF, NUM_DEF)
    if args.update:
        pkgdir = path.dirname(path.abspath(__file__))
        gen.update(pkgdir)
    else:
        if args.python:
            lines = gen.iter_lines_py()
        else:
            lines = gen.iter_lines_c()
        for line in lines:
            print(line)

