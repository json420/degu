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

from collections import namedtuple

Table = namedtuple('Table', 'name r_ignore items')
BitFlag = namedtuple('BitFlag', 'bit name data')
BitMask = namedtuple('BitMask', 'mask name flags data')
Classifier = namedtuple('Classifier', 'flags masks table') 

COOKIE = b' -/0123456789:;=ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'



# For case-folding and validating header names:
NAMES_DEF = b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
VALUES_DEF = bytes(sorted(NAMES_DEF + b' !"#$%&\'()*+,./:;<=>?@[\\]^_`{|}~'))


# Generic bit-flag based validation table with 7 sets, plus 1 error set:
FLAGS_DEF = (
    ('DIGIT', b'0123456789'),
    ('ALPHA', b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'),
    ('PATH',  b'-.:_~'),
    ('QUERY', b'%&+='),
    ('URI', b'/?'),
    ('SPACE', b' '),
    ('VAL', b'"\'()*,;[]'),   
)
MASKS_DEF = (
    ('DIGIT', ('DIGIT',)),
    ('PATH', ('DIGIT', 'ALPHA', 'PATH')),
    ('QUERY', ('DIGIT', 'ALPHA', 'PATH', 'QUERY')),
    ('URI', ('DIGIT', 'ALPHA', 'PATH', 'QUERY', 'URI')),
    ('REASON', ('DIGIT', 'ALPHA', 'SPACE')),
    ('VAL', ('DIGIT', 'ALPHA', 'PATH', 'QUERY', 'URI', 'SPACE', 'VAL')),
)


def check_flag_data(f):
    sdata = bytes(sorted(set(f.data)))
    if f.data != sdata:
        raise ValueError(
            '{}: {!r} != {!r}'.format(f.name, f.data, sdata)
        )


def build_flags(flags_def):
    assert 0 < len(flags_def) < 8
    accum = []
    for (i, (name, data)) in enumerate(flags_def):
        bit = 2 ** i
        assert bit in (1, 2, 4, 8, 16, 32, 64)
        accum.append(BitFlag(bit, name, data))
    return tuple(accum)


def normalized_bytes(source):
    return bytes(sorted(set(source)))


def check_disjoint(accum, allowed):
    allowed_s = normalized_bytes(allowed)
    if allowed != allowed_s:
        raise ValueError(
            '{!r} != {!r}'.format(allowed, allowed_s)
        )
    common = set(accum).intersection(allowed)
    if common:
        raise ValueError(
            'non-empty intersection: {!r}'.format(sorted(common))
        )


def build_masks(flags, masks_def):
    accum = []
    _map = dict((f.name, f) for f in flags)
    for (name, parts) in masks_def:
        bits = 0
        union = set()
        for p in parts:
            f = _map[p]
            bits |= f.bit
            check_disjoint(union, f.data)
            union.update(f.data)
        mask = 255 ^ bits
        data = normalized_bytes(union)
        assert len(data) == len(union)
        accum.append(BitMask(mask, name, parts, data))
    return tuple(accum)


def build_table(flags):
    assert 1 < len(flags) < 8
    table = {}
    for f in flags:
        check_flag_data(f)
        assert set(table).isdisjoint(f.data)
        table.update((key, f.bit) for key in f.data)
    for key in range(256):
        table.setdefault(key, 128)
    assert len(table) == 256
    items = tuple(sorted(table.items()))
    return Table('_FLAGS', 128, items)


def build_classifier(flags_def, masks_def):
    flags = build_flags(flags_def)
    masks = build_masks(flags, masks_def)
    table = build_table(flags)
    return Classifier(flags, masks, table)


def _iter_names_table(allowed, casefold):
    assert isinstance(allowed, bytes)
    assert isinstance(casefold, bool)
    for i in range(256):
        if 32 <= i <= 127 and i in allowed:
            r = (ord(chr(i).lower()) if casefold else i)
            yield (i, r)
        else:
            yield (i, 255)


def build_names_table(allowed, casefold):
    items = tuple(_iter_names_table(allowed, casefold))
    return Table('_NAMES', 255, items)


def format_values(line):
    return ','.join('{:>3}'.format(r) for (i, r) in line)


def iter_help(line, r_ignore):
    for (i, r) in line:
        if r == r_ignore:
            yield ' ' * 4  # 4 spaces
        else:
            yield '{!r:<4}'.format(chr(i))


def needs_help(line, r_ignore):
    for (i, r) in line:
        if r != r_ignore:
            return True
    return False


def format_help(line, r_ignore):
    if needs_help(line, r_ignore):
        return ' '.join(iter_help(line, r_ignore))


def iter_lines(table, comment):
    assert table.r_ignore in (255, 128)
    line = []
    for item in table.items:
        line.append(item)
        if len(line) == 8:
            text = '    {},'.format(format_values(line))
            help = format_help(line, table.r_ignore)
            if help:
                yield '{} {}  {}'.format(text, comment, help.rstrip())
            else:
                yield text
            line = []
    assert not line


def iter_c(table):
    yield 'static const uint8_t {}[{:d}] = {{'.format(table.name, len(table.items))
    yield from iter_lines(table, '//')
    yield '};'


def iter_p(name, definition, r_ignore=255):
    yield '{} = ('.format(name)
    yield from iter_lines(definition, '#', r_ignore)
    yield ')'



def iter_flags(flags):
    width = max(len(f.name) for f in flags)
    yield '/*'
    for f in flags:
        name = f.name.ljust(width)
        yield ' * {} {:>2} {:08b}  {!r}'.format(name, f.bit, f.bit, f.data)
    yield ' */'


def mask_name(name):
    assert 'mask' not in name.lower()
    return name + '_MASK'


def iter_masks(masks):
    width = max(len(mask_name(m.name)) for m in masks)
    for m in masks:
        name = m.name.ljust(width)
        line = '#define {} {:>3}  // {:08b} '.format(name, m.mask, m.mask)
        if m.flags is None:
            yield line
        else:
            yield line + ' ~({})'.format('|'.join(m.flags))


def iter_classifier(obj):
    yield from iter_flags(obj.flags)
    yield from iter_masks(obj.masks)
    yield from iter_c(obj.table)


def iter_py_mask_sets(masks):
    for m in masks:
        name = '_' + m.name
        line = '{} = frozenset({!r})'.format(name, m.data)
        if len(line) <= 80:
            yield line
        else:
            yield '{} = frozenset(\n    {!r}\n)'.format(name, m.data)


def iter_all(classifier, names_table):
    (begin, end) = build_marker_comments('/', '*')
    yield begin
    yield ''
    yield from iter_c(names_table)
    yield ''
    yield ''
    yield from iter_classifier(classifier)
    yield ''
    yield end
    yield ''
    yield from iter_mask_sets(classifier.masks)


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
            label.rjust(width),
            (' ' * 4),
        ])
        needfill = 80 - len(line) - 1
        line += (fill * needfill) + end
        markers.append(line)
    return tuple(markers)


class TheWorks:
    def __init__(self, names_def, flags_def, masks_def):
        self.table = build_names_table(names_def, True)
        self.obj = build_classifier(flags_def, masks_def)

    def iter_lines_py(self):
        yield from iter_py_mask_sets(self.obj.masks)
        


if __name__ == '__main__':
    import argparse
    import os
    from os import path

    pkgdir = path.dirname(path.abspath(__file__))
    orig = path.join(pkgdir, '_base.c')
    tmp = orig + '.updated-tables.new'
    bak = orig + '.updated-tables.old'

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', default=False,
        help='generate Python tables (instead of C)'
    )
    parser.add_argument('--update', action='store_true', default=False,
        help='update tables in _base.c, _basepy.py'
    )
    args = parser.parse_args()
    iter_x = (iter_p if args.p else iter_c)

    dawerks = TheWorks(NAMES_DEF, FLAGS_DEF, MASKS_DEF)

    if not args.update:
        for line in dawerks.iter_lines_py():
            print(line)
        raise SystemExit('nope')

    text = open(orig, 'r').read()
    inlines = text.splitlines()
    outlines = []

    (begin, end) = build_marker_comments('/', '*')
    found = False
    for line in inlines:
        if line.startswith(begin):
            assert not found
            found = True
        if found:
            print('- ' + line)
        else:
            outlines.append(line)
        if line.startswith(end):
            assert found
            found = False
            outlines.extend(iter_all(classifier, names_table))

    with open(tmp, 'x') as fp:
        fp.write('\n'.join(outlines) + '\n')
    os.rename(orig, bak)
    os.rename(tmp, orig)

            

#    for line in iter_all(classifier, names_table):
#        print(line)
        
    print(pkgdir)
