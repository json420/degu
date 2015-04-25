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
Unit tests for the `degu.base` module`
"""

from unittest import TestCase
import os
import io
import sys
from random import SystemRandom

from . import helpers
from .helpers import DummySocket, random_chunks, FuzzTestCase, iter_bad, MockSocket
from .helpers import random_chunks2, random_chunk, random_data, MockSocket2
from degu.sslhelpers import random_id
from degu.base import _MAX_LINE_SIZE
from degu import base, _basepy


# True if the C extension is available
try:
    from degu import _base
    C_EXT_AVAIL = True
except ImportError:
    _base = None
    C_EXT_AVAIL = False


random = SystemRandom()

class UserInt(int):
    pass


MAX_LENGTH = int('9' * 16)
MAX_UINT64 = 2**64 - 1
assert 0 < MAX_LENGTH < MAX_UINT64
BAD_LENGTHS = (
    -MAX_UINT64 - 1,
    -MAX_UINT64,
    -MAX_LENGTH - 1,
    -MAX_LENGTH,
    -17,
    -1,
    MAX_LENGTH + 1,
    MAX_UINT64,
    MAX_UINT64 + 1,
)
CRLF = b'\r\n'
TERM = CRLF * 2
TYPE_ERROR = '{}: need a {!r}; got a {!r}: {!r}'


BAD_HEADER_LINES = (
    b'K:V\r\n',
    b'K V\r\n',
    b': V\r\n',
    b'K: \r\n',
    b': \r\n',
)

GOOD_HEADERS = (
    (
        b'Content-Type: application/json\r\n',
        ('content-type', 'application/json')
    ),
    (
        b'Content-Length: 17\r\n',
        ('content-length', 17)
    ),
    (
        b'Content-Length: 0\r\n',
        ('content-length', 0)
    ),
    (
        b'Transfer-Encoding: chunked\r\n',
        ('transfer-encoding', 'chunked')
    ),
    (
        b'User-Agent: Microfiber/14.12.0 (Ubuntu 14.04; x86_64)\r\n',
        ('user-agent', 'Microfiber/14.12.0 (Ubuntu 14.04; x86_64)')
    ),
    (
        b'Host: 192.168.1.171:5984\r\n',
        ('host', '192.168.1.171:5984')
    ),
    (
        b'Host: [fe80::e8b:fdff:fe75:402c/64]:5984\r\n',
        ('host', '[fe80::e8b:fdff:fe75:402c/64]:5984')
    ),
    (
        b'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n',
        ('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
    ),
    (
        b'Date: Sat, 27 Dec 2014 01:12:48 GMT\r\n',
        ('date', 'Sat, 27 Dec 2014 01:12:48 GMT')
    ),
    (
        b'Content-Type: text/html;charset=utf-8\r\n',
        ('content-type', 'text/html;charset=utf-8')
    ),
)


def _permute_remove(method):
    if len(method) <= 1:
        return
    for i in range(len(method)):
        m = bytearray(method)
        del m[i]
        m = bytes(m)
        yield m
        yield from _permute_remove(m)


def _permute_replace(method):
    for i in range(len(method)):
        for j in range(256):
            if method[i] == j:
                continue
            m = bytearray(method)
            m[i] = j
            yield bytes(m)


def _permute_insert(method):
    for i in range(len(method) + 1):
        for j in range(256):
            m = bytearray(method)
            m.insert(i, j)
            yield bytes(m)


GOOD_METHODS = (
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'DELETE',
)
_functions = (_permute_remove, _permute_replace, _permute_insert)
BAD_METHODS = [
    b'',
    b'TRACE',
    b'OPTIONS',
    b'CONNECT',
    b'PATCH',
]
BAD_METHODS.extend(m.encode().lower() for m in GOOD_METHODS)
for func in _functions:
    for m in GOOD_METHODS:
        BAD_METHODS.extend(func(m.encode()))
BAD_METHODS = tuple(sorted(set(BAD_METHODS)))


# Pre-build bad preamble termination permutations:
def _iter_bad_term(term):
    for i in range(len(term)):
        bad = bytearray(term)
        del bad[i]
        yield bytes(bad)
        g = term[i]
        for b in range(256):
            if b == g:
                continue
            bad = bytearray(term)
            bad[i] = b
            yield bytes(bad)

BAD_TERM = tuple(_iter_bad_term(b'\r\n\r\n'))


def random_headers(count):
    return dict(
        ('X-' + random_id(), random_id()) for i in range(count)
    )


def build_header_lines(headers):
    return ''.join(
        '{}: {}\r\n'.format(key, value) for (key, value) in headers.items()
    ).encode('latin_1')


def casefold_headers(headers):
    """
    For example:

    >>> casefold_headers({'FOO': 'BAR'})
    {'foo': 'BAR'}

    """
    return dict(
        (key.casefold(), value) for (key, value) in headers.items()
    )


def random_line():
    return '{}\r\n'.format(random_id()).encode()


def random_header_line():
    return '{}: {}\r\n'.format(random_id(), random_id()).encode()


def random_lines(header_count=15):
    first_line = random_id()
    header_lines = [random_id() for i in range(header_count)]
    return (first_line, header_lines)


def encode_preamble(first_line, header_lines):
    lines = [first_line + '\r\n']
    lines.extend(line + '\r\n' for line in header_lines)
    lines.append('\r\n')
    return ''.join(lines).encode('latin_1')


def random_body():
    size = random.randint(1, 34969)
    return os.urandom(size)


class AlternatesTestCase(FuzzTestCase):
    def skip_if_no_c_ext(self):
        if not C_EXT_AVAIL:
            self.skipTest('cannot import `degu._base` C extension')


class BackendTestCase(TestCase):
    backend = _basepy

    def setUp(self):
        backend = self.backend
        name = self.__class__.__name__
        if name.endswith('_Py'):
            self.assertIs(backend, _basepy)
        elif name.endswith('_C'):
            self.assertIs(backend, _base)
        else:
            raise Exception(
                'bad BackendTestCase subclass name: {!r}'.format(name)
            )
        if backend is None:
            self.skipTest('cannot import `degu._base` C extension')

    def getattr(self, name):
        backend = self.backend
        self.assertIn(backend, (_basepy, _base))
        self.assertIsNotNone(backend)
        if not hasattr(backend, name):
            raise Exception(
                '{!r} has no attribute {!r}'.format(backend.__name__, name)
            )
        # FIXME: check imported alias in degu.base (when needed)
        return getattr(backend, name)


class TestRange_Py(BackendTestCase):
    @property
    def Range(self):
        return self.getattr('Range')

    def test_init(self):
        # start isn't an int:
        for bad in ['16', 16.0, UserInt(16), None]:
            with self.assertRaises(TypeError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('start', int, type(bad), bad)
            )

        # stop isn't an int:
        for bad in ['21', 21.0, UserInt(21), None]:
            with self.assertRaises(TypeError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('stop', int, type(bad), bad)
            )

        # start < 0, stop < 0:
        for bad in [-1, -2, -9999999999999999]:
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )

        # start > max64, stop > max64:
        max64 = 2**64 - 1
        for offset in [1, 2, 3]:
            bad = max64 + offset
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {!r}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {!r}'.format(bad)
            )

        # start > max_length, stop > max_length:
        max_length = int('9' * 16)
        for bad in [max_length + 1, max_length + 2, max64]:
            with self.assertRaises(ValueError) as cm:
                self.Range(bad, 21)
            self.assertEqual(str(cm.exception),
                'need 0 <= start <= 9999999999999999; got {}'.format(bad)
            )
            with self.assertRaises(ValueError) as cm:
                self.Range(16, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= stop <= 9999999999999999; got {}'.format(bad)
            )

        # start >= stop:
        bad_pairs = (
            (0, 0),
            (1, 0),
            (17, 17),
            (18, 17),
            (9999999999999998, 9999999999999998),
            (9999999999999999, 9999999999999998),
        )
        for (start, stop) in bad_pairs:
            with self.assertRaises(ValueError) as cm:
                self.Range(start, stop)
            self.assertEqual(str(cm.exception),
                'need start < stop; got {} >= {}'.format(start, stop)
            )

        # All good:
        r = self.Range(16, 21)
        self.assertIs(type(r.start), int)
        self.assertIs(type(r.stop), int)
        self.assertEqual(r.start, 16)
        self.assertEqual(r.stop, 21)
        self.assertEqual(repr(r), 'Range(16, 21)')
        self.assertEqual(str(r), 'bytes=16-20')

        r = self.Range(0, max_length)
        self.assertIs(type(r.start), int)
        self.assertIs(type(r.stop), int)
        self.assertEqual(r.start, 0)
        self.assertEqual(r.stop, max_length)
        self.assertEqual(repr(r), 'Range(0, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=0-9999999999999998')

        # Check reference counting:
        if self.backend is _base:
            delmsg = 'readonly attribute'
        else:
            delmsg = "can't delete attribute"
        for i in range(1000):
            stop = random.randrange(1, max_length + 1)
            start = random.randrange(0, stop)
            stop_cnt = sys.getrefcount(stop)
            start_cnt = sys.getrefcount(start)

            r = self.Range(start, stop)
            self.assertIs(type(r.start), int)
            self.assertIs(type(r.stop), int)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(repr(r), 'Range({}, {})'.format(start, stop))
            self.assertEqual(str(r), 'bytes={}-{}'.format(start, stop - 1))
            del r
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)

            # start, stop should be read-only:
            r = self.Range(start, stop)
            for name in ('start', 'stop'):
                with self.assertRaises(AttributeError) as cm:
                    delattr(r, name)
                self.assertEqual(str(cm.exception), delmsg)
            del r
            self.assertEqual(sys.getrefcount(start), start_cnt)
            self.assertEqual(sys.getrefcount(stop), stop_cnt)

    def test_repr_and_str(self):
        r = self.Range(0, 1)
        self.assertEqual(repr(r), 'Range(0, 1)')
        self.assertEqual(str(r),  'bytes=0-0')

        r = self.Range(0, 9999999999999999)
        self.assertEqual(repr(r), 'Range(0, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=0-9999999999999998')

        r = self.Range(9999999999999998, 9999999999999999)
        self.assertEqual(repr(r), 'Range(9999999999999998, 9999999999999999)')
        self.assertEqual(str(r),  'bytes=9999999999999998-9999999999999998')

    def test_cmp(self):
        def iter_types(pairs):
            for (start, stop) in pairs:
                yield (start, stop)
                yield self.Range(start, stop)
                yield 'bytes={}-{}'.format(start, stop - 1)

        r = self.Range(16, 21)
        equals   = tuple(iter_types([(16, 21)]))
        lessers  = tuple(iter_types([(15, 21), (16, 20)]))
        greaters = tuple(iter_types([(17, 21), (16, 22)]))

        # __lt__():
        for o in lessers:
            self.assertIs(r < o, False)
            self.assertIs(o < r, True)
        for o in equals:
            self.assertIs(r < o, False)
            self.assertIs(o < r, False)
        for o in greaters:
            self.assertIs(r < o, True)
            self.assertIs(o < r, False)

        # __le__():
        for o in lessers:
            self.assertIs(r <= o, False)
            self.assertIs(o <= r, True)
        for o in equals:
            self.assertIs(r <= o, True)
            self.assertIs(o <= r, True)
        for o in greaters:
            self.assertIs(r <= o, True)
            self.assertIs(o <= r, False)

        # __eq__():
        for o in lessers:
            self.assertIs(r == o, False)
            self.assertIs(o == r, False)
        for o in equals:
            self.assertIs(r == o, True)
            self.assertIs(o == r, True)
        for o in greaters:
            self.assertIs(r == o, False)
            self.assertIs(o == r, False)

        # __ne__():
        for o in lessers:
            self.assertIs(r != o, True)
            self.assertIs(o != r, True)
        for o in equals:
            self.assertIs(r != o, False)
            self.assertIs(o != r, False)
        for o in greaters:
            self.assertIs(r != o, True)
            self.assertIs(o != r, True)

        # __gt__():
        for o in lessers:
            self.assertIs(r > o, True)
            self.assertIs(o > r, False)
        for o in equals:
            self.assertIs(r > o, False)
            self.assertIs(o > r, False)
        for o in greaters:
            self.assertIs(r > o, False)
            self.assertIs(o > r, True)

        # __ge__():
        for o in lessers:
            self.assertIs(r >= o, True)
            self.assertIs(o >= r, False)
        for o in equals:
            self.assertIs(r >= o, True)
            self.assertIs(o >= r, True)
        for o in greaters:
            self.assertIs(r >= o, False)
            self.assertIs(o >= r, True)


class TestRange_C(TestRange_Py):
    backend = _base


def _iter_sep_permutations(good=b': '):
    (g0, g1) = good
    yield bytes([g0])
    yield bytes([g1])
    for v in range(256):
        yield bytes([v, g1])
        yield bytes([g0, v])

SEP_PERMUTATIONS = tuple(_iter_sep_permutations())

def _iter_crlf_permutations(good=b'\r\n'):
    (g0, g1) = good
    yield bytes([g0])
    yield bytes([g1])
    for v in range(256):
        yield bytes([v, g1])
        yield bytes([g0, v])

CRLF_PERMUTATIONS = tuple(_iter_crlf_permutations())


class TestParsingFunctions_Py(BackendTestCase):
    def test_parse_chunk_size(self):
        parse_chunk_size  = self.getattr('parse_chunk_size')
        HEX = b'0123456789ABCDEFabcdef'
        for num in range(256):
            lcase = '{:x}'.format(num).encode()
            ucase = '{:X}'.format(num).encode()
            self.assertEqual(lcase, lcase.lower())
            self.assertEqual(ucase, ucase.upper())
            for src in (lcase, ucase):
                n = parse_chunk_size(src)
                self.assertIs(type(n), int)
                self.assertEqual(n, num)
                for i in range(len(src)):
                    tmp = bytearray(src)
                    for b in range(256):
                        tmp[i] = b
                        new = bytes(tmp)
                        if b in HEX and (new[0] != 48 or len(new) == 1):
                            n = parse_chunk_size(new)
                            self.assertIs(type(n), int)
                            self.assertEqual(n, int(new, 16))
                        else:
                            with self.assertRaises(ValueError) as cm:
                                parse_chunk_size(new)
                            self.assertEqual(str(cm.exception),
                                'bad chunk_size: {!r}'.format(new)
                            )

        diff = 100
        iomax = 16 * 1024 * 1024
        for num in range(iomax - diff, iomax + diff):
            src = '{:x}'.format(num).encode()
            if num > iomax:
                with self.assertRaises(ValueError) as cm:
                    parse_chunk_size(src)
                self.assertEqual(str(cm.exception),
                    'need chunk_size <= {}; got {}'.format(iomax, num)
                )
            else:
                n = parse_chunk_size(src)
                self.assertIs(type(n), int)
                self.assertEqual(n, num)

        hmax = int(b'f' * 7, 16)
        self.assertEqual(hmax, 268435455)
        self.assertEqual(len('{:x}'.format(hmax)), 7)
        self.assertEqual(len('{:x}'.format(hmax + 1)), 8)
        for num in range(hmax - diff, hmax + diff):
            src = '{:x}'.format(num).encode()
            with self.assertRaises(ValueError) as cm:
                parse_chunk_size(src)
            if num > hmax:
                self.assertEqual(str(cm.exception),
                    'chunk_size is too long: {!r}...'.format(src[:7])
                )
            else:
                self.assertEqual(str(cm.exception),
                    'need chunk_size <= {}; got {}'.format(iomax, num)
                )

    def test_parse_chunk_extension(self):
        parse_chunk_extension = self.getattr('parse_chunk_extension')
        EXTKEY = _basepy.EXTKEY
        EXTVAL = _basepy.EXTVAL
        self.assertEqual(parse_chunk_extension(b'k=v'), ('k', 'v'))
        self.assertEqual(parse_chunk_extension(b'key=value'), ('key', 'value'))

        for bad in (b'', b'k', b'kv', b'kev', b'keyvalue', b'k=', b'=v'):
            with self.assertRaises(ValueError) as cm:
                parse_chunk_extension(bad)
            self.assertEqual(str(cm.exception),
                'bad chunk extension: {!r}'.format(bad)
            )

        def random_allowed(allowed, min_len, max_len):
            assert type(allowed) is frozenset
            assert type(min_len) is int and min_len > 0
            assert type(max_len) is int and max_len > min_len
            for size in range(min_len, max_len):
                yield bytes(random.sample(allowed, size))

        keys = tuple(random_allowed(EXTKEY, 1, 16))
        vals = tuple(random_allowed(EXTVAL, 1, 16))
        for key in keys:
            k = key.decode()
            for val in vals:
                v = val.decode()
                good = key + b'=' + val
                self.assertEqual(parse_chunk_extension(good), (k, v))
                for b in range(256):
                    sep = bytes([b])
                    bad = key + sep + val
                    if b == 61:
                        self.assertEqual(bad, good)
                        continue
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(bad)
                    self.assertEqual(str(cm.exception),
                        'bad chunk extension: {!r}'.format(bad)
                    )

        ALL = frozenset(range(256))
        badkey = ALL - EXTKEY
        badval = ALL - EXTVAL
        for (key, val) in [(b'k', b'v'), (b'key', b'value')]:
            for i in range(len(key)):
                tmp = bytearray(key)
                for b in badkey:
                    tmp[i] = b
                    bad = bytes(tmp)
                    ext = b'='.join([bad, val])
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(ext)
                    if b == 61:
                        if i > 0:
                            self.assertEqual(str(cm.exception),
                                'bad chunk extension value: {!r}'.format(
                                    ext[i+1:]
                                )
                            )
                        else:
                            self.assertEqual(str(cm.exception),
                                'bad chunk extension: {!r}'.format(ext)
                            ) 
                    else:
                        self.assertEqual(str(cm.exception),
                            'bad chunk extension key: {!r}'.format(bad)
                        )
            for i in range(len(val)):
                tmp = bytearray(val)
                for b in badval:
                    tmp[i] = b
                    bad = bytes(tmp)
                    ext = b'='.join([key, bad])
                    with self.assertRaises(ValueError) as cm:
                        parse_chunk_extension(ext)
                    self.assertEqual(str(cm.exception),
                        'bad chunk extension value: {!r}'.format(bad)
                    )

    def test_parse_chunk(self):
        parse_chunk = self.getattr('parse_chunk')
        self.assertEqual(parse_chunk(b'0'), (0, None))
        self.assertEqual(parse_chunk(b'0;k=v'), (0, ('k', 'v')))

        self.assertEqual(parse_chunk(b'1000000'), (16777216, None))
        self.assertEqual(parse_chunk(b'1000000;k=v'), (16777216, ('k', 'v')))

        with self.assertRaises(ValueError) as cm:
            parse_chunk(b'')
        self.assertEqual(str(cm.exception), "b'\\r\\n' not found in b''...")
        with self.assertRaises(ValueError) as cm:
            parse_chunk(b';k=v')
        self.assertEqual(str(cm.exception), "bad chunk_size: b''")
        with self.assertRaises(ValueError) as cm:
            parse_chunk(b'0;')
        self.assertEqual(str(cm.exception), "bad chunk extension: b''")

        tmp = bytearray(b'0;k=v')
        for b in range(256):
            tmp[1] = b
            src = bytes(tmp)
            if b == 59:
                self.assertEqual(parse_chunk(src), (0, ('k', 'v')))
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_chunk(src)
                self.assertEqual(str(cm.exception),
                    'bad chunk_size: {!r}'.format(src)
                )

    def test_parse_range(self):
        parse_range = self.getattr('parse_range')
        Range = self.getattr('Range')

        prefix = b'bytes='
        ranges = (
            (0, 1),
            (0, 2),
            (9, 10),
            (9, 11),
            (0, 9999999999999999),
            (9999999999999998, 9999999999999999),
        )
        for (start, stop) in ranges:
            suffix = '-'.join([str(start), str(stop - 1)]).encode()
            src = prefix + suffix
            r = parse_range(src)
            self.assertIs(type(r), Range)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(r, (start, stop))

            for i in range(len(prefix)):
                g = prefix[i]
                bad = bytearray(prefix)
                for b in range(256):
                    bad[i] = b
                    src = bytes(bad) + suffix
                    if g == b:
                        r = parse_range(src)
                        self.assertIs(type(r), Range)
                        self.assertEqual(r.start, start)
                        self.assertEqual(r.stop, stop)
                        self.assertEqual(r, (start, stop))
                    else:
                        with self.assertRaises(ValueError) as cm:
                            parse_range(src)
                        self.assertEqual(str(cm.exception),
                            'bad range: {!r}'.format(src)
                        )

            b_start = str(start).encode()
            b_end = str(stop - 1).encode()
            for b in range(256):
                sep = bytes([b])
                src = prefix + b_start + sep + b_end
                if sep == b'-':
                    r = parse_range(src)
                    self.assertIs(type(r), Range)
                    self.assertEqual(r.start, start)
                    self.assertEqual(r.stop, stop)
                    self.assertEqual(r, (start, stop))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_range(src)
                    self.assertEqual(str(cm.exception),
                        'bad range: {!r}'.format(src)
                    )

        # end < start
        for i in range(2000):
            stop = random.randrange(1, MAX_LENGTH + 1)
            start = stop - 1
            good = 'bytes={}-{}'.format(start, stop - 1).encode()
            r = parse_range(good)
            self.assertIs(type(r), Range)
            self.assertEqual(r.start, start)
            self.assertEqual(r.stop, stop)
            self.assertEqual(str(r), good.decode())
            self.assertEqual(r, (start, stop))
            bad = 'bytes={}-{}'.format(start, stop - 2).encode()
            with self.assertRaises(ValueError) as cm:
                parse_range(bad)
            self.assertEqual(str(cm.exception), 'bad range: {!r}'.format(bad))

        # end > (MAX_LENGTH - 1)
        stop = MAX_LENGTH
        start = stop - 1
        good = 'bytes={}-{}'.format(start, stop - 1).encode()
        r = parse_range(good)
        self.assertIs(type(r), Range)
        self.assertEqual(r.start, start)
        self.assertEqual(r.stop, stop)
        self.assertEqual(str(r), good.decode())
        self.assertEqual(r, (start, stop))
        bad = 'bytes={}-{}'.format(start, stop).encode()
        with self.assertRaises(ValueError) as cm:
            parse_range(bad)
        self.assertEqual(str(cm.exception), 'bad range: {!r}'.format(bad))

    def test_parse_headers(self):
        parse_headers = self.getattr('parse_headers')

        self.assertEqual(parse_headers(b''), {})
        self.assertEqual(parse_headers(b'K: V'), {'k': 'V'})
        with self.assertRaises(ValueError) as cm:
            parse_headers(b': V')
        self.assertEqual(str(cm.exception), "header line too short: b': V'")
        with self.assertRaises(ValueError) as cm:
            parse_headers(b': VV')
        self.assertEqual(str(cm.exception), 'header name is empty')
        with self.assertRaises(ValueError) as cm:
            parse_headers(b'K: ')
        self.assertEqual(str(cm.exception), "header line too short: b'K: '")
        with self.assertRaises(ValueError) as cm:
            parse_headers(b'KK: ')
        self.assertEqual(str(cm.exception), 'header value is empty')

        length =  b'Content-Length: 17'
        encoding = b'Transfer-Encoding: chunked'
        _range = b'Range: bytes=16-16'
        _type = b'Content-Type: text/plain'
        self.assertEqual(parse_headers(length),
            {'content-length': 17}
        )
        self.assertEqual(parse_headers(encoding),
            {'transfer-encoding': 'chunked'}
        )
        self.assertEqual(parse_headers(_type),
            {'content-type': 'text/plain'}
        )
        self.assertEqual(parse_headers(b'\r\n'.join([_type, length])),
            {'content-type': 'text/plain', 'content-length': 17}
        )
        self.assertEqual(parse_headers(b'\r\n'.join([_type, encoding])),
            {'content-type': 'text/plain', 'transfer-encoding': 'chunked'}
        )
        h = parse_headers(_range)
        self.assertEqual(h, {'range': (16, 17)})
        self.assertEqual(h, {'range': 'bytes=16-16'})
        self.assertIsInstance(h['range'], self.getattr('Range'))
        self.assertEqual(h['range'].start, 16)
        self.assertEqual(h['range'].stop, 17)
        self.assertEqual(repr(h['range']), 'Range(16, 17)')
        self.assertEqual(str(h['range']), 'bytes=16-16')

        badsrc = b'\r\n'.join([length, encoding])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot have both content-length and transfer-encoding headers'
        )
        badsrc = b'\r\n'.join([length, _range])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot include range header and content-length/transfer-encoding'
        )
        badsrc = b'\r\n'.join([encoding, _range])
        with self.assertRaises(ValueError) as cm:
            parse_headers(badsrc)
        self.assertEqual(str(cm.exception),
            'cannot include range header and content-length/transfer-encoding'
        )

        key = b'Content-Length'
        val = b'17'
        self.assertEqual(len(SEP_PERMUTATIONS), 514)
        good_count = 0
        for sep in SEP_PERMUTATIONS:
            line = b''.join([key, sep, val])
            if sep == b': ':
                good_count += 1
                self.assertEqual(parse_headers(line), {'content-length': 17})
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_headers(line)
                self.assertEqual(str(cm.exception),
                    'bad header line: {!r}'.format(line)
                )
        self.assertEqual(good_count, 2)

        self.assertEqual(len(CRLF_PERMUTATIONS), 514)
        good_count = 0
        for crlf in CRLF_PERMUTATIONS:
            src1 = b''.join([length, crlf, _type])
            src2 = b''.join([_type, crlf, length])
            if crlf == b'\r\n':
                good_count += 1
                self.assertEqual(parse_headers(src1),
                    {'content-type': 'text/plain', 'content-length': 17}
                )
                self.assertEqual(parse_headers(src2),
                    {'content-type': 'text/plain', 'content-length': 17}
                )
            else:
                badval1 = b''.join([b'17', crlf, _type])
                with self.assertRaises(ValueError) as cm:
                    parse_headers(src1)
                self.assertEqual(str(cm.exception),
                    'content-length too long: {!r}...'.format(badval1[:16])
                )
                badval2 = b''.join([b'text/plain', crlf, length])
                with self.assertRaises(ValueError) as cm:
                    parse_headers(src2)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header value: {!r}'.format(badval2)
                )
        self.assertEqual(good_count, 2)

    def test_parse_request(self):
        bodies = base.bodies
        parse_request = self.getattr('parse_request')
        EmptyPreambleError = self.getattr('EmptyPreambleError')
        RequestType = self.getattr('RequestType')
        Range = self.getattr('Range')
        rfile = io.BytesIO()

        with self.assertRaises(EmptyPreambleError) as cm:
            parse_request(b'', rfile, bodies)
        self.assertEqual(str(cm.exception), 'request preamble is empty')

        r = parse_request(b'GET / HTTP/1.1', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)
        self.assertEqual(r, ('GET', '/', {}, None, [], [], None))

        r = parse_request(b'GET / HTTP/1.1\r\nRange: bytes=17-20', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/')
        self.assertEqual(r.headers, {'range': 'bytes=17-20'})
        self.assertIsNone(r.body)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, [])
        self.assertIsNone(r.query)
        self.assertEqual(r,
            ('GET', '/', {'range': 'bytes=17-20'}, None, [], [], None)
        )
        _range = r.headers['range']
        self.assertIs(type(_range), Range)
        self.assertEqual(_range.start, 17)
        self.assertEqual(_range.stop, 21)
        self.assertEqual(_range, (17, 21))
        self.assertEqual(_range, 'bytes=17-20')
        self.assertEqual(repr(_range), 'Range(17, 21)')
        self.assertEqual(str(_range), 'bytes=17-20')

        r = parse_request(b'GET /foo? HTTP/1.1', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo?')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, ['foo'])
        self.assertEqual(r.query, '')
        self.assertEqual(r, ('GET', '/foo?', {}, None, [], ['foo'], ''))

        r = parse_request(b'GET /foo/bar/?stuff=junk HTTP/1.1', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'GET')
        self.assertEqual(r.uri, '/foo/bar/?stuff=junk')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, ['foo', 'bar', ''])
        self.assertEqual(r.query, 'stuff=junk')
        self.assertEqual(r,
            ('GET', '/foo/bar/?stuff=junk', {}, None, [], ['foo', 'bar', ''], 'stuff=junk')
        )

        r = parse_request(b'PUT /foo HTTP/1.1', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)
        self.assertEqual(r, ('PUT', '/foo', {}, None, [], ['foo'], None))

        r = parse_request(b'PUT /foo HTTP/1.1\r\nContent-Length: 17', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {'content-length': 17})
        self.assertIs(type(r.body), bodies.Body)
        self.assertIs(r.body.rfile, rfile)
        self.assertEqual(r.body.content_length, 17)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)
        self.assertEqual(r,
            ('PUT', '/foo', {'content-length': 17}, r.body, [], ['foo'], None)
        )

        r = parse_request(b'PUT /foo HTTP/1.1\r\nTransfer-Encoding: chunked', rfile, bodies)
        self.assertIs(type(r), RequestType)
        self.assertEqual(r.method, 'PUT')
        self.assertEqual(r.uri, '/foo')
        self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
        self.assertIs(type(r.body), bodies.ChunkedBody)
        self.assertIs(r.body.rfile, rfile)
        self.assertEqual(r.script, [])
        self.assertEqual(r.path, ['foo'])
        self.assertIsNone(r.query)
        self.assertEqual(r,
            ('PUT', '/foo', {'transfer-encoding': 'chunked'}, r.body, [], ['foo'], None)
        )

    def test_parse_response(self):
        bodies = base.bodies
        parse_response = self.getattr('parse_response')
        EmptyPreambleError = self.getattr('EmptyPreambleError')
        ResponseType = self.getattr('ResponseType')
        rfile = io.BytesIO()

        with self.assertRaises(EmptyPreambleError) as cm:
            parse_response('GET', b'', rfile, bodies)
        self.assertEqual(str(cm.exception), 'response preamble is empty')

        r = parse_response('GET', b'HTTP/1.1 200 OK', rfile, bodies)
        self.assertIs(type(r), ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {})
        self.assertIsNone(r.body)

        body_methods = ('GET', 'PUT', 'POST', 'DELETE')
        length = b'HTTP/1.1 200 OK\r\nContent-Length: 17'

        r = parse_response('HEAD', length, rfile, bodies)
        self.assertIs(type(r), ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'content-length': 17})
        self.assertIsNone(r.body)

        for method in body_methods:
            r = parse_response(method, length, rfile, bodies)
            self.assertIs(type(r), ResponseType)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.reason, 'OK')
            self.assertEqual(r.headers, {'content-length': 17})
            self.assertIs(type(r.body), bodies.Body)
            self.assertIs(r.body.rfile, rfile)
            self.assertEqual(r.body.content_length, 17)

        chunked = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked'

        r = parse_response('HEAD', chunked, rfile, bodies)
        self.assertIs(type(r), ResponseType)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.reason, 'OK')
        self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
        self.assertIsNone(r.body)

        for method in body_methods:
            r = parse_response(method, chunked, rfile, bodies)
            self.assertIs(type(r), ResponseType)
            self.assertEqual(r.status, 200)
            self.assertEqual(r.reason, 'OK')
            self.assertEqual(r.headers, {'transfer-encoding': 'chunked'})
            self.assertIs(type(r.body), bodies.ChunkedBody)
            self.assertIs(r.body.rfile, rfile)


class TestParsingFunctions_C(TestParsingFunctions_Py):
    backend = _base


class TestMiscFunctions_Py(BackendTestCase):
    def test_readchunk(self):
        readchunk  = self.getattr('readchunk')
 
        # rfile.readline missing:
        class MissingReadline:
            def read(self, size):
                assert False
        rfile = MissingReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingReadline' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.readline() not callable:
        class BadReadline:
            readline = 'hello'
            def read(self):
                assert False
        rfile = BadReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.read missing:
        class MissingRead:
            def readline(self, size):
                assert False
        rfile = MissingRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingRead' object has no attribute 'read'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # rfile.read() not callable:
        class BadRead:
            read = 'hello'
            def readline(self, size):
                assert False
        rfile = BadRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception), 'rfile.read() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'0\r\n\r\n')
        self.assertEqual(readchunk(rfile), (None, b''))
        self.assertEqual(sys.getrefcount(rfile), 2)
        rfile = io.BytesIO(b'0;key=value\r\n\r\n')
        self.assertEqual(readchunk(rfile), (('key', 'value'), b''))
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c\r\nhello, world\r\n')
        self.assertEqual(readchunk(rfile), (None, b'hello, world'))
        self.assertEqual(sys.getrefcount(rfile), 2)
        rfile = io.BytesIO(b'c;key=value\r\nhello, world\r\n')
        self.assertEqual(readchunk(rfile), (('key', 'value'), b'hello, world'))
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() dosen't return bytes:
        class Bad1:
            def readline(self, size):
                assert type(size) is int and size == 4096
                return bytearray(b'c\r\n')
            def read(self, size):
                assert False
        rfile = Bad1()
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            'need a {!r}; readline() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # what readline() returns doesn't contain a b'\r\n':
        class Bad2:
            def __init__(self, line):
                self.__line = line
            def readline(self, size):
                assert type(size) is int and size == 4096
                return self.__line
            def read(self, size):
                assert False
        for bad in (b'', b'\n', b'c', b'c\rhello, world', b'c\nhello, world'):
            rfile = Bad2(bad)
            with self.assertRaises(ValueError) as cm:
                readchunk(rfile)
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad)
            )
            self.assertEqual(sys.getrefcount(rfile), 2)

        # read() dosen't return bytes:
        class Bad3:
            def __init__(self, data):
                self.__data = data
            def readline(self, size):
                assert type(size) is int and size == 4096
                return b'c\r\n'
            def read(self, size):
                assert type(size) is int and size == 14
                return self.__data

        ret = bytearray(b'hello, world\r\n')
        self.assertEqual(len(ret), 14)
        rfile = Bad3(ret)
        with self.assertRaises(TypeError) as cm:
            readchunk(rfile)
        self.assertEqual(str(cm.exception),
            'need a {!r}; read() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # read() doesn't return the correct amount of data:
        for bad in (b'', b'hello world\r\n', os.urandom(13), os.urandom(15)):
            rfile = Bad3(bad)
            with self.assertRaises(ValueError) as cm:
                readchunk(rfile)
            self.assertEqual(str(cm.exception),
                'read() returned {} bytes, need 14'.format(len(bad))
            ) 
            self.assertEqual(sys.getrefcount(rfile), 2)

    def test_write_chunk(self):
        write_chunk  = self.getattr('write_chunk')

        def getrefcounts(wfile, chunk):
            counts = {
                'wfile': sys.getrefcount(wfile),
                'chunk': sys.getrefcount(chunk),
                'chunk[0]': sys.getrefcount(chunk[0]),
                'chunk[1]': sys.getrefcount(chunk[1]),
            }
            if chunk[0] is not None:
                counts['chunk[0][0]'] = sys.getrefcount(chunk[0][0])
                counts['chunk[0][1]'] = sys.getrefcount(chunk[0][1])
            return counts

        wfile = io.BytesIO()
        chunk = (None, b'')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 5)
        self.assertEqual(wfile.getvalue(), b'0\r\n\r\n')
        self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (('k', 'v'), b'')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 9)
        self.assertEqual(wfile.getvalue(), b'0;k=v\r\n\r\n')
        self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (None, b'hello, world')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 17)
        self.assertEqual(wfile.getvalue(), b'c\r\nhello, world\r\n')
        self.assertEqual(getrefcounts(wfile, chunk), counts)

        wfile = io.BytesIO()
        chunk = (('k', 'v'), b'hello, world')
        counts = getrefcounts(wfile, chunk)
        self.assertEqual(write_chunk(wfile, chunk), 21)
        self.assertEqual(wfile.getvalue(), b'c;k=v\r\nhello, world\r\n')
        self.assertEqual(getrefcounts(wfile, chunk), counts)


class TestMiscFunctions_C(TestMiscFunctions_Py):
    backend = _base


class dict_subclass(dict):
    pass

class str_subclass(str):
    pass

class int_subclass(int):
    pass


class TestFormatting_Py(BackendTestCase):
    def test_set_default_header(self):
        set_default_header = self.getattr('set_default_header')

        # key not yet present:
        headers = {}
        key = random_id().lower()
        rawval = random_id(20)
        val1 = rawval[:24]
        self.assertEqual(sys.getrefcount(key), 2)
        self.assertEqual(sys.getrefcount(val1), 2)
        self.assertIsNone(set_default_header(headers, key, val1))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)

        # same val instance:
        self.assertIsNone(set_default_header(headers, key, val1))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)

        # equal val but different val instance:
        val2 = rawval[:24]
        self.assertIsNot(val2, val1)
        self.assertEqual(val2, val1)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertIsNone(set_default_header(headers, key, val2))
        self.assertEqual(headers, {key: val1})
        self.assertIs(headers[key], val1)
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)
        self.assertEqual(sys.getrefcount(val2), 2)

        # non-equal val:
        val3 = random_id()
        self.assertNotEqual(val3, val2)
        self.assertEqual(sys.getrefcount(val3), 2)
        with self.assertRaises(ValueError) as cm:
            set_default_header(headers, key, val3)
        self.assertEqual(str(cm.exception),
            '{!r} mismatch: {!r} != {!r}'.format(key, val3, val1)
        )
        self.assertEqual(sys.getrefcount(key), 3)
        self.assertEqual(sys.getrefcount(val1), 3)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertEqual(sys.getrefcount(val3), 2)

        # delete headers:
        del headers
        self.assertEqual(sys.getrefcount(key), 2)
        self.assertEqual(sys.getrefcount(val1), 2)
        self.assertEqual(sys.getrefcount(val2), 2)
        self.assertEqual(sys.getrefcount(val3), 2)

    def test_format_headers(self):
        format_headers = self.getattr('format_headers')

        # Bad headers type:
        bad = [('foo', 'bar')]
        with self.assertRaises(TypeError) as cm:
            format_headers(bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, list, bad)
        )
        bad = dict_subclass({'foo': 'bar'})
        with self.assertRaises(TypeError) as cm:
            format_headers(bad)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('headers', dict, dict_subclass, bad)
        )

        good_items = (
            None,
            ('content-length', 17),
            ('foo', 'bar'),
        )
        good = dict()
        for item in good_items:
            if item:
                (key, value) = item
                good[key] = value

            # Bad key type:
            headers = {b'foo': 'bar'}
            headers.update(good)
            with self.assertRaises(TypeError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('key', str, bytes, b'foo')
            )
            headers = {str_subclass('foo'): 'bar'}
            headers.update(good)
            with self.assertRaises(TypeError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('key', str, str_subclass, 'foo')
            )

            # key contains non-ascii codepoints:
            headers = {'¡': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: '¡'")
            headers = {'™': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: '™'")

            # key is not lowercase:
            headers = {'Foo': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: 'Foo'")
            headers = {'f\no': 'bar'}
            headers.update(good)
            with self.assertRaises(ValueError) as cm:
                format_headers(headers)
            self.assertEqual(str(cm.exception), "bad key: 'f\\no'")

        self.assertEqual(format_headers({}), '')
        self.assertEqual(format_headers({'foo': 17}), 'foo: 17\r\n')
        self.assertEqual(
            format_headers({'foo': 17, 'bar': 18}),
            'bar: 18\r\nfoo: 17\r\n'
        )
        self.assertEqual(
            format_headers({'foo': '17', 'bar': '18'}),
            'bar: 18\r\nfoo: 17\r\n'
        )

    def test_format_chunk(self):
        format_chunk = self.getattr('format_chunk')
        MAX_IO_SIZE = self.getattr('MAX_IO_SIZE')

        # chunk isn't a tuple:
        chunk = [None, b'']
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk must be a {!r}; got a {!r}'.format(tuple, list)
        )

        # chunk isn't a 2-tuple:
        for chunk in [tuple(), (None,), (None, b'', b'hello')]:
            with self.assertRaises(ValueError) as cm:
                format_chunk(chunk)
            self.assertEqual(str(cm.exception),
                'chunk must be a 2-tuple; got a {}-tuple'.format(len(chunk))
            )

        # chunk[0] isn't a tuple:
        chunk = (['key', 'value'], b'')
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk[0] must be a {!r}; got a {!r}'.format(tuple, list)
        )

        # chunk[0] isn't a 2-tuple:
        for ext in [tuple(), ('foo',), ('foo', 'bar', 'baz')]:
            chunk = (ext, b'')
            with self.assertRaises(ValueError) as cm:
                format_chunk(chunk)
            self.assertEqual(str(cm.exception),
                'chunk[0] must be a 2-tuple; got a {}-tuple'.format(len(ext))
            )

        # chunk[1] isn't bytes:
        chunk = (None, bytearray())
        with self.assertRaises(TypeError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'chunk[1] must be a {!r}; got a {!r}'.format(bytes, bytearray)
        )

        # len(chunk[1]) > MAX_IO_SIZE:
        data = b'D' * (MAX_IO_SIZE + 1)
        chunk = (None, data)
        with self.assertRaises(ValueError) as cm:
            format_chunk(chunk)
        self.assertEqual(str(cm.exception),
            'need len(chunk[1]) <= {}; got {}'.format(MAX_IO_SIZE, len(data))
        )

        ext = ('k', 'v')
        self.assertEqual(format_chunk((None, b'')), b'0\r\n')
        self.assertEqual(format_chunk((ext, b'')), b'0;k=v\r\n')

        data = b'hello, world'
        self.assertEqual(format_chunk((None, data)), b'c\r\n')
        self.assertEqual(format_chunk((ext, data)), b'c;k=v\r\n')

        data = b'D' * (MAX_IO_SIZE)
        self.assertEqual(format_chunk((None, data)),
            '{:x}\r\n'.format(MAX_IO_SIZE).encode()  
        )
        self.assertEqual(format_chunk((ext, data)),
            '{:x};k=v\r\n'.format(MAX_IO_SIZE).encode()  
        )


class TestFormatting_C(TestFormatting_Py):
    backend = _base


class TestNamedTuples_Py(BackendTestCase):
    def new(self, name, count):
        args = tuple(random_id() for i in range(count))
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)
        tup = self.getattr(name)(*args)
        self.assertIsInstance(tup, tuple)
        self.assertIsInstance(tup, self.getattr(name + 'Type'))
        self.assertEqual(tup, args)
        self.assertEqual(len(tup), count)
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        return (tup, args)

    def test_Bodies(self):
        (tup, args) = self.new('Bodies', 4)
        self.assertIs(tup.Body,            args[0])
        self.assertIs(tup.BodyIter,        args[1])
        self.assertIs(tup.ChunkedBody,     args[2])
        self.assertIs(tup.ChunkedBodyIter, args[3])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)

    def test_Request(self):
        (tup, args) = self.new('Request', 7)
        self.assertIs(tup.method,  args[0])
        self.assertIs(tup.uri,     args[1])
        self.assertIs(tup.headers, args[2])
        self.assertIs(tup.body,    args[3])
        self.assertIs(tup.script,  args[4])
        self.assertIs(tup.path,    args[5])
        self.assertIs(tup.query,   args[6])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)

    def test_Response(self):
        (tup, args) = self.new('Response', 4)
        self.assertIs(tup.status,  args[0])
        self.assertIs(tup.reason,  args[1])
        self.assertIs(tup.headers, args[2])
        self.assertIs(tup.body,    args[3])
        for a in args:
            self.assertEqual(sys.getrefcount(a), 4)
        del tup
        for a in args:
            self.assertEqual(sys.getrefcount(a), 3)


class TestNamedTuples_C(TestNamedTuples_Py):
    backend = _base


MiB = 1024 * 1024

class TestConstants(TestCase):
    def check_power_of_two(self, name, size):
        self.assertIsInstance(size, int, name)
        self.assertGreaterEqual(size, 1024, name)
        self.assertLessEqual(size, MiB * 32, name)
        self.assertFalse(size & (size - 1),
            '({}) {:d} is not a power of 2'.format(name, size)
        )

    def check_size_constant(self, name, min_size=4096, max_size=16777216):
        self.check_power_of_two('min_size', min_size)
        self.check_power_of_two('max_size', max_size)
        self.assertEqual(name[-5:], '_SIZE', name)
        self.assertTrue(name.isupper(), '{!r} not uppercase'.format(name))
        size = getattr(base, name)
        self.check_power_of_two(name, size)
        self.assertGreaterEqual(size, min_size, name)
        self.assertLessEqual(size, max_size, name)

    def test__MAX_LINE_SIZE(self):
        self.assertIsInstance(base._MAX_LINE_SIZE, int)
        self.assertGreaterEqual(base._MAX_LINE_SIZE, 1024)
        self.assertEqual(base._MAX_LINE_SIZE % 1024, 0)
        self.assertLessEqual(base._MAX_LINE_SIZE, 8192)

    def test_STREAM_BUFFER_SIZE(self):
        self.assertIsInstance(base.STREAM_BUFFER_SIZE, int)
        self.assertEqual(base.STREAM_BUFFER_SIZE % 4096, 0)
        self.assertGreaterEqual(base.STREAM_BUFFER_SIZE, 4096)

    def test_MAX_READ_SIZE(self):
        self.check_size_constant('MAX_READ_SIZE')

    def test_MAX_CHUNK_SIZE(self):
        self.check_size_constant('MAX_CHUNK_SIZE')

    def test_IO_SIZE(self):
        self.check_size_constant('IO_SIZE')

    def test_bodies(self):
        self.assertIsInstance(base.bodies, tuple)
        self.assertIsInstance(base.bodies, base.BodiesType)

        self.assertIs(base.bodies.Body, base.Body)
        self.assertIs(base.bodies.BodyIter, base.BodyIter)
        self.assertIs(base.bodies.ChunkedBody, base.ChunkedBody)
        self.assertIs(base.bodies.ChunkedBodyIter, base.ChunkedBodyIter)

        self.assertIs(base.bodies[0], base.Body)
        self.assertIs(base.bodies[1], base.BodyIter)
        self.assertIs(base.bodies[2], base.ChunkedBody)
        self.assertIs(base.bodies[3], base.ChunkedBodyIter)

        self.assertEqual(base.bodies,
            (base.Body, base.BodyIter, base.ChunkedBody, base.ChunkedBodyIter)
        )


class TestEmptyPreambleError(TestCase):
    def test_init(self):
        e = base.EmptyPreambleError('stuff and junk')
        self.assertIsInstance(e, Exception)
        self.assertIsInstance(e, ConnectionError)
        self.assertIs(type(e), base.EmptyPreambleError)
        self.assertEqual(str(e), 'stuff and junk')


class FuzzTestFunctions(AlternatesTestCase):
    def test_read_chunk(self):
        self.fuzz(base.read_chunk)


class DummyFile:
    def __init__(self, lines):
        self._lines = lines
        self._calls = []

    def readline(self, size=None):
        self._calls.append(size)
        return self._lines.pop(0)


class DummyWriter:
    def __init__(self):
        self._calls = []

    def write(self, data):
        assert isinstance(data, bytes)
        self._calls.append(('write', data))
        return len(data)

    def flush(self):
        self._calls.append('flush')


class UserBytes(bytes):
    pass


class TestFunctions(AlternatesTestCase):
    def test_makefiles(self):
        sock = DummySocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        (reader, writer) = base._makefiles(sock, base.bodies)
        self.assertIsInstance(reader, base.Reader)
        self.assertIsInstance(writer, base.Writer)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 4)
        del reader
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 3)
        del writer
        self.assertEqual(sock._calls, [])
        self.assertEqual(sys.getrefcount(sock), 2)

    def check_parse_method(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_method = backend.parse_method

        for method in GOOD_METHODS:
            # Input is str:
            result = parse_method(method)
            self.assertIs(type(result),  str)
            self.assertEqual(result, method)
            self.assertIs(parse_method(method), result)

            # Input is bytes:
            result = parse_method(method.encode())
            self.assertIs(type(result),  str)
            self.assertEqual(result, method)
            self.assertIs(parse_method(method), result)

            # Lowercase str:
            with self.assertRaises(ValueError) as cm:
                parse_method(method.lower())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

            # Lowercase bytes:
            with self.assertRaises(ValueError) as cm:
                parse_method(method.lower().encode())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method.lower().encode())
            )

        # Static bad methods:
        bad_methods = (
            'OPTIONS',
            'TRACE',
            'CONNECT',
            'FOO',
            'BAR',
            'COPY',
            'FOUR',
            'SIXSIX',
            'FOOBAR',
            '',
        )
        for bad in bad_methods:
            # Bad str:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

            # Bad bytes:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad.encode())
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad.encode())
            )

        # Pre-generated bad method permutations:
        for bad in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:
                parse_method(bad)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(bad)
            )

        # Random bad bytes:
        for size in range(1, 20):
            for i in range(100):
                bad = os.urandom(size)
                with self.assertRaises(ValueError) as cm:
                    parse_method(bad)
                self.assertEqual(str(cm.exception),
                    'bad HTTP method: {!r}'.format(bad)
                )

    def test_parse_method_py(self):
        self.check_parse_method(_basepy)

    def test_parse_method_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_method(_base)

    def check_parse_uri(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_uri = backend.parse_uri

        # Empty b'':
        with self.assertRaises(ValueError) as cm:
            parse_uri(b'')
        self.assertEqual(str(cm.exception), 'uri is empty')

        # URI does not start with /:
        with self.assertRaises(ValueError) as cm:
            parse_uri(b'foo')
        self.assertEqual(str(cm.exception), "path[0:1] != b'/': b'foo'")

        # Empty path component:
        double_slashers = (
            b'//',
            b'//foo',
            b'//foo/',
            b'//foo/bar',
            b'//foo/bar/',
            b'/foo//',
            b'/foo//bar',
            b'/foo//bar/',
            b'/foo/bar//',
        )
        for bad in double_slashers:
            for suffix in (b'', b'?', b'?q'):
                with self.assertRaises(ValueError) as cm:
                    parse_uri(bad + suffix)
                self.assertEqual(str(cm.exception),
                    "b'//' in path: {!r}".format(bad)
                )

        ret = parse_uri(b'/')
        self.assertIsInstance(ret, tuple)
        self.assertEqual(len(ret), 4)
        self.assertEqual(ret, ('/', [], [] , None))
        self.assertEqual(sys.getrefcount(ret[1]), 2)
        self.assertEqual(sys.getrefcount(ret[2]), 2)

        self.assertEqual(parse_uri(b'/'), ('/', [], [] , None))
        self.assertEqual(parse_uri(b'/?'), ('/?', [], [] , ''))
        self.assertEqual(parse_uri(b'/?q'), ('/?q', [], [] , 'q'))

        self.assertEqual(parse_uri(b'/foo'), ('/foo', [], ['foo'], None))
        self.assertEqual(parse_uri(b'/foo?'), ('/foo?', [], ['foo'], ''))
        self.assertEqual(parse_uri(b'/foo?q'), ('/foo?q', [], ['foo'], 'q'))

        self.assertEqual(parse_uri(b'/foo/'), ('/foo/', [], ['foo', ''], None))
        self.assertEqual(parse_uri(b'/foo/?'), ('/foo/?', [], ['foo', ''], ''))
        self.assertEqual(parse_uri(b'/foo/?q'),
            ('/foo/?q', [], ['foo', ''], 'q')
        )

        self.assertEqual(parse_uri(b'/foo/bar'),
            ('/foo/bar', [], ['foo', 'bar'], None)
        )
        self.assertEqual(parse_uri(b'/foo/bar?'),
             ('/foo/bar?', [], ['foo', 'bar'], '')
        )
        self.assertEqual(parse_uri(b'/foo/bar?q'),
             ('/foo/bar?q', [], ['foo', 'bar'], 'q')
        )
        self.assertEqual(parse_uri(b'/~novacut/+archive/ubuntu/daily'),
            (
                '/~novacut/+archive/ubuntu/daily',
                [],
                ['~novacut', '+archive', 'ubuntu', 'daily'],
                None
            )
        )

    def test_parse_uri_py(self):
        self.check_parse_uri(_basepy)

    def test_parse_uri_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_uri(_base)

    def check_parse_header_name(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_header_name = backend.parse_header_name

        # Empty bytes:
        with self.assertRaises(ValueError) as cm:
            parse_header_name(b'')
        self.assertEqual(str(cm.exception), 'header name is empty')

        # Too long:
        good = b'R' * 32
        bad =  good + b'Q'
        self.assertEqual(parse_header_name(good), good.decode().lower())
        with self.assertRaises(ValueError) as cm:
            parse_header_name(bad)
        self.assertEqual(str(cm.exception),
            'header name too long: {!r}...'.format(good)
        )

        # Too short, just right, too long:
        for size in range(69):
            buf = b'R' * size
            if 1 <= size <= 32:
                self.assertEqual(parse_header_name(buf), buf.decode().lower())
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_header_name(buf)
                if size == 0:
                    self.assertEqual(str(cm.exception), 'header name is empty')
                else:
                    self.assertEqual(str(cm.exception),
                        "header name too long: b'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'..."
                    )

        # Start with a know good value, then for each possible bad byte value,
        # copy the good value and make it bad by replacing a good byte with a
        # bad byte at each possible index:
        goodset = frozenset(
            b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
        )
        badset = frozenset(range(256)) - goodset
        good = b'Super-Transfer-Encoding'
        self.assertEqual(parse_header_name(good), 'super-transfer-encoding')
        for b in badset:
            for i in range(len(good)):
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                with self.assertRaises(ValueError) as cm:
                    parse_header_name(bad)
                self.assertEqual(str(cm.exception),
                    'bad bytes in header name: {!r}'.format(bad)
                )

    def test_parse_header_name_py(self):
        self.check_parse_header_name(_basepy)

    def test_parse_header_name_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_header_name(_base)

        # Compare C to Python implementations with the same random values:
        functions = (_base.parse_header_name, _basepy.parse_header_name)
        for i in range(1000):
            bad = os.urandom(32)
            for func in functions:
                exc = 'bad bytes in header name: {!r}'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception), exc, func.__module__)
            bad2 = bad + b'R'
            for func in functions:
                exc = 'header name too long: {!r}...'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad2)
                self.assertEqual(str(cm.exception), exc, func.__module__)
        for i in range(5000):
            good = bytes(random.sample(_basepy.NAME, 32))
            for func in functions:
                ret = func(good)
                self.assertIsInstance(ret, str)
                self.assertEqual(ret, good.decode().lower())

    def check_parse_response_line(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_response_line = backend.parse_response_line

        # request line is too short:
        line  = b'HTTP/1.1 200 OK'
        for stop in range(15):
            short = line[:stop]
            self.assertTrue(0 <= len(short) <= 14)
            with self.assertRaises(ValueError) as cm:
                parse_response_line(short)
            self.assertEqual(str(cm.exception),
                'response line too short: {!r}'.format(short)
            )

        # Double confirm when len(line) is 0:
        with self.assertRaises(ValueError) as cm:
            parse_response_line(b'')
        self.assertEqual(str(cm.exception),
            "response line too short: b''"
        )

        # Double confirm when len(line) is 14:
        short = line[:14]
        self.assertEqual(len(short), 14)
        with self.assertRaises(ValueError) as cm:
            parse_response_line(short)
        self.assertEqual(str(cm.exception),
            "response line too short: b'HTTP/1.1 200 O'"
        )

        # Confirm valid minimum response line is 15 bytes in length:
        self.assertEqual(len(line), 15)
        self.assertEqual(parse_response_line(line), (200, 'OK'))

        # Test all status in range 000-999, plus a few valid reasons:
        for status in range(1000):
            for reason in ('OK', 'Not Found', 'Enhance Your Calm'):
                line = 'HTTP/1.1 {:03d} {}'.format(status, reason).encode()
                if 100 <= status <= 599:
                    self.assertEqual(parse_response_line(line), (status, reason))
                else:
                    with self.assertRaises(ValueError) as cm:
                        parse_response_line(line)
                    self.assertEqual(str(cm.exception),
                        'bad status: {!r}'.format('{:03d}'.format(status).encode())
                    )

        # Test fast-path when reason is 'OK':
        for status in range(200, 600):
            line = 'HTTP/1.1 {} OK'.format(status).encode()
            tup = parse_response_line(line)
            self.assertEqual(tup, (status, 'OK'))
            self.assertIs(parse_response_line(line)[1], tup[1])

        # Permutations:
        good = b'HTTP/1.1 200 OK'
        self.assertEqual(parse_response_line(good), (200, 'OK'))
        for i in range(len(good)):
            bad = bytearray(good)
            del bad[i]
            with self.assertRaises(ValueError):
                parse_response_line(bytes(bad))
            for j in range(32):
                bad = bytearray(good)
                bad[i] = j
                with self.assertRaises(ValueError):
                    parse_response_line(bytes(bad))

    def test_parse_response_line_py(self):
        self.check_parse_response_line(_basepy)

    def test_parse_response_line_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_response_line(_base)

    def check_parse_request_line(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_request_line = backend.parse_request_line
        self.assertEqual(parse_request_line(b'GET / HTTP/1.1'),
            ('GET', '/', [], [], None)
        )

    def test_parse_request_line_py(self):
        self.check_parse_request_line(_basepy)

    def test_parse_request_line_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_request_line(_base)

    def check_parse_content_length(self, backend):
        self.assertIn(backend, (_base, _basepy))
        parse_content_length = backend.parse_content_length

        # Empty bytes:
        with self.assertRaises(ValueError) as cm:
            parse_content_length(b'')
        self.assertEqual(str(cm.exception), 'content-length is empty')

        # Too long:
        good = b'1111111111111111'
        bad =  b'11111111111111112'
        self.assertEqual(parse_content_length(good), 1111111111111111)
        with self.assertRaises(ValueError) as cm:
            parse_content_length(bad)
        self.assertEqual(str(cm.exception),
            "content-length too long: b'1111111111111111'..."
        )

        # Too short, just right, too long:
        for size in range(50):
            buf = b'1' * size
            if 1 <= size <= 16:
                self.assertEqual(parse_content_length(buf), int(buf))
            else:
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(buf)
                if size == 0:
                    self.assertEqual(str(cm.exception), 'content-length is empty')
                else:
                    self.assertEqual(str(cm.exception),
                        "content-length too long: b'1111111111111111'..."
                    )

        # b'0' should work fine:
        self.assertEqual(parse_content_length(b'0'), 0)

        # Non-leading zeros should work fine:
        somegood = (
            b'10',
            b'100',
            b'101',
            b'909',
            b'1000000000000000',
            b'1000000000000001',
            b'9000000000000000',
            b'9000000000000009',
        )
        for good in somegood:
            self.assertEqual(parse_content_length(good), int(good))

        # But leading zeros should raise a ValueError:
        somebad = (
            b'01',
            b'09',
            b'011',
            b'099',
            b'0111111111111111',
            b'0999999999999999',
            b'0000000000000001',
            b'0000000000000009',
        )
        for bad in somebad:
            with self.assertRaises(ValueError) as cm:
                parse_content_length(bad)
            self.assertEqual(str(cm.exception),
                'content-length has leading zero: {!r}'.format(bad)
            )

        # Netative values and spaces should be reported with the 'bad bytes'
        # ValueError message:
        somebad = (
            b'-1',
            b'-17',
            b' 1',
            b'1 ',
            b'              -1',
            b'-900719925474099',
        )
        for bad in somebad:
            with self.assertRaises(ValueError) as cm:
                parse_content_length(bad)
            self.assertEqual(str(cm.exception),
                'bad bytes in content-length: {!r}'.format(bad)
            )

        # Start with a know good value, then for each possible bad byte value,
        # copy the good value and make it bad by replacing a good byte with a
        # bad byte at each possible index:
        goodset = frozenset(b'0123456789')
        badset = frozenset(range(256)) - goodset
        good = b'9007199254740992'
        self.assertEqual(parse_content_length(good), 9007199254740992)
        for b in badset:
            for i in range(len(good)):
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(bad)
                self.assertEqual(str(cm.exception),
                    'bad bytes in content-length: {!r}'.format(bad)
                )

        good_values = (
            b'0',
            b'1',
            b'9',
            b'11',
            b'99',
            b'1111111111111111',
            b'9007199254740992',
            b'9999999999999999',
        )
        for good in good_values:
            self.assertEqual(parse_content_length(good), int(good))
            self.assertEqual(str(int(good)).encode(), good)
            for bad in iter_bad(good, b'0123456789'):
                with self.assertRaises(ValueError) as cm:
                    parse_content_length(bad)
                self.assertEqual(str(cm.exception),
                    'bad bytes in content-length: {!r}'.format(bad)
                )
        for good in (b'1', b'9', b'11', b'99', b'10', b'90'):
            for also_good in helpers.iter_good(good, b'123456789'):
                self.assertEqual(
                    parse_content_length(also_good),
                    int(also_good)
                )

    def test_parse_content_length_py(self):
        self.check_parse_content_length(_basepy)

    def test_parse_content_length_c(self):
        self.skip_if_no_c_ext()
        self.check_parse_content_length(_base)

        # Compare C to Python implementations with the same random values:
        functions = (_base.parse_content_length, _basepy.parse_content_length)
        for i in range(1000):
            bad = os.urandom(16)
            for func in functions:
                exc = 'bad bytes in content-length: {!r}'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad)
                self.assertEqual(str(cm.exception), exc, func.__module__)
            bad2 = bad + b'1'
            for func in functions:
                exc = 'content-length too long: {!r}...'.format(bad)
                with self.assertRaises(ValueError) as cm:
                    func(bad2)
                self.assertEqual(str(cm.exception), exc, func.__module__)
        for i in range(5000):
            goodval = random.randint(0, 9007199254740992)
            good = str(goodval).encode()
            for func in functions:
                ret = func(good)
                self.assertIsInstance(ret, int)
                self.assertEqual(ret, goodval)

    def check_format_request(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_request()
        with self.assertRaises(TypeError):
            backend.format_request('GET')
        with self.assertRaises(TypeError):
            backend.format_request('GET', '/foo')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_request('GET', '/foo', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_request('GET', '/foo', {}),
            b'GET /foo HTTP/1.1\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_request('PUT', '/foo', headers),
            b'PUT /foo HTTP/1.1\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_request('POST', '/foo', headers),
            b'POST /foo HTTP/1.1\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_request_py(self):
        self.check_format_request(_basepy)

    def test_format_request_c(self):
        self.skip_if_no_c_ext()
        self.check_format_request(_base)

    def check_format_response(self, backend):
        # Too few arguments:
        with self.assertRaises(TypeError):
            backend.format_response()
        with self.assertRaises(TypeError):
            backend.format_response(200)
        with self.assertRaises(TypeError):
            backend.format_response(200, 'OK')

        # Too many arguments:
        with self.assertRaises(TypeError):
            backend.format_response('200', 'OK', {}, None)

        # No headers:
        self.assertEqual(
            backend.format_response(200, 'OK', {}),
            b'HTTP/1.1 200 OK\r\n\r\n'
        )

        # One header:
        headers = {'content-length': 1776}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n'
        )

        # Two headers:
        headers = {'content-length': 1776, 'a': 'A'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

        # Three headers:
        headers = {'content-length': 1776, 'a': 'A', 'z': 'Z'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ncontent-length: 1776\r\nz: Z\r\n\r\n'
        )
        headers = {'transfer-encoding': 'chunked', 'z': 'Z', 'a': 'A'}
        self.assertEqual(
            backend.format_response(200, 'OK', headers),
            b'HTTP/1.1 200 OK\r\na: A\r\ntransfer-encoding: chunked\r\nz: Z\r\n\r\n'
        )

    def test_format_response_py(self):
        self.check_format_response(_basepy)

    def test_format_response_c(self):
        self.skip_if_no_c_ext()
        self.check_format_response(_base)

    def test_read_chunk(self):
        data = (b'D' * 7777)  # Longer than _MAX_LINE_SIZE
        small_data = (b'd' * 6666)  # Still longer than _MAX_LINE_SIZE
        termed = data + b'\r\n'
        self.assertEqual(len(termed), 7779)
        size = b'1e61\r\n'
        size_plus = b'1e61;foo=bar\r\n'

        # No CRLF terminated chunk size line:
        rfile = io.BytesIO(termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'DD'"
        )
        self.assertEqual(rfile.tell(), _MAX_LINE_SIZE)
        self.assertFalse(rfile.closed)

        # Size line has LF but no CR:
        rfile = io.BytesIO(b'1e61\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b'1\\n'"
        )
        self.assertEqual(rfile.tell(), 5)
        self.assertFalse(rfile.closed)

        # Totally empty:
        rfile = io.BytesIO(b'')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size termination: b''"
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertFalse(rfile.closed)

        # Size line is property terminated, but empty value:
        rfile = io.BytesIO(b'\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b''"
        )
        self.assertEqual(rfile.tell(), 2)
        self.assertFalse(rfile.closed)

        # Too many b';' is size line:
        rfile = io.BytesIO(b'foo;bar;baz\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "bad chunk size line: b'foo;bar;baz\\r\\n'"
        )
        self.assertEqual(rfile.tell(), 13)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Size isn't a hexidecimal integer:
        rfile = io.BytesIO(b'17.6\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 6)
        self.assertFalse(rfile.closed)
        rfile = io.BytesIO(b'17.6;1e61=bar\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            "invalid literal for int() with base 16: b'17.6'"
        )
        self.assertEqual(rfile.tell(), 15)
        self.assertFalse(rfile.closed)

        # Size is negative:
        rfile = io.BytesIO(b'-1\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got -1'.format(base.MAX_CHUNK_SIZE)
        )
        self.assertEqual(rfile.tell(), 4)
        self.assertFalse(rfile.closed)
        rfile = io.BytesIO(b'-1e61;1e61=bar\r\n' + termed)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= {}; got -7777'.format(base.MAX_CHUNK_SIZE)
        )
        self.assertEqual(rfile.tell(), 16)
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_SIZE:
        line = '{:x}\r\n'.format(base.MAX_CHUNK_SIZE + 1)
        rfile = io.BytesIO(line.encode('latin_1') + data)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= 16777216; got 16777217'
        )
        self.assertEqual(rfile.tell(), len(line))
        self.assertFalse(rfile.closed)

        # Size > MAX_CHUNK_SIZE, with extension:
        line = '{:x};foo=bar\r\n'.format(base.MAX_CHUNK_SIZE + 1)
        rfile = io.BytesIO(line.encode('latin_1') + data)
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need 0 <= chunk_size <= 16777216; got 16777217'
        )
        self.assertEqual(rfile.tell(), len(line))
        self.assertFalse(rfile.closed)

        # Too few b'=' in chunk extension:
        rfile = io.BytesIO(b'1e61;foo\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'need more than 1 value to unpack'
        )
        self.assertEqual(rfile.tell(), 10)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Too many b'=' in chunk extension:
        rfile = io.BytesIO(b'1e61;foo=bar=baz\r\ndata\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception),
            'too many values to unpack (expected 2)'
        )
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(rfile.read(), b'data\r\n')

        # Not enough data:
        rfile = io.BytesIO(size + small_data + b'\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), 'underflow: 6668 < 7777')
        self.assertEqual(rfile.tell(), 6674)
        self.assertFalse(rfile.closed)

        # Data isn't properly terminated:
        rfile = io.BytesIO(size + data + b'TT\r\n')
        with self.assertRaises(ValueError) as cm:
            base.read_chunk(rfile)
        self.assertEqual(str(cm.exception), "bad chunk data termination: b'TT'")
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when it's all good:
        rfile = io.BytesIO(size + termed)
        self.assertEqual(base.read_chunk(rfile), (None, data))
        self.assertEqual(rfile.tell(), 7785)
        self.assertFalse(rfile.closed)

        # Test when size line has extra information:
        rfile = io.BytesIO(size_plus + termed)
        self.assertEqual(base.read_chunk(rfile), (('foo', 'bar'), data))
        self.assertEqual(rfile.tell(), 7793)
        self.assertFalse(rfile.closed)

        # Test max chunk size:
        data = os.urandom(base.MAX_CHUNK_SIZE)
        line = '{:x}\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (None, data))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

        # Again, with extension:
        data = os.urandom(base.MAX_CHUNK_SIZE)
        line = '{:x};foo=bar\r\n'.format(len(data))
        rfile = io.BytesIO()
        rfile.write(line.encode('latin_1'))
        rfile.write(data)
        rfile.write(b'\r\n')
        rfile.seek(0)
        self.assertEqual(base.read_chunk(rfile), (('foo', 'bar'), data))
        self.assertEqual(rfile.tell(), len(line) + len(data) + 2)

    def test_write_chunk(self):
        # len(data) > MAX_CHUNK_SIZE:
        data = b'D' * (base.MAX_CHUNK_SIZE + 1)
        wfile = io.BytesIO()
        chunk = (None, data)
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, chunk)
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # len(data) > MAX_CHUNK_SIZE, but now with extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), data)
        with self.assertRaises(ValueError) as cm:
            base.write_chunk(wfile, chunk)
        self.assertEqual(str(cm.exception),
            'need len(data) <= 16777216; got 16777217'
        )
        self.assertEqual(wfile.getvalue(), b'')

        # Empty data:
        wfile = io.BytesIO()
        chunk = (None, b'')
        self.assertEqual(base.write_chunk(wfile, chunk), 5)
        self.assertEqual(wfile.getvalue(), b'0\r\n\r\n')

        # Empty data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'),  b'')
        self.assertEqual(base.write_chunk(wfile, chunk), 13)
        self.assertEqual(wfile.getvalue(), b'0;foo=bar\r\n\r\n')

        # Small data:
        wfile = io.BytesIO()
        chunk = (None, b'hello')
        self.assertEqual(base.write_chunk(wfile, chunk), 10)
        self.assertEqual(wfile.getvalue(), b'5\r\nhello\r\n')

        # Small data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), b'hello')
        self.assertEqual(base.write_chunk(wfile, chunk), 18)
        self.assertEqual(wfile.getvalue(), b'5;foo=bar\r\nhello\r\n')

        # Larger data:
        data = b'D' * 7777
        wfile = io.BytesIO()
        chunk = (None, data)
        self.assertEqual(base.write_chunk(wfile, chunk), 7785)
        self.assertEqual(wfile.getvalue(), b'1e61\r\n' + data + b'\r\n')

        # Larger data plus extension:
        wfile = io.BytesIO()
        chunk = (('foo', 'bar'), data)
        self.assertEqual(base.write_chunk(wfile, chunk), 7793)
        self.assertEqual(wfile.getvalue(), b'1e61;foo=bar\r\n' + data + b'\r\n')

        # Test random value round-trip with read_chunk():
        for size in range(1776):
            # No extension:
            data = os.urandom(size)
            total = size + len('{:x}'.format(size)) + 4
            fp = io.BytesIO()
            chunk = (None, data)
            self.assertEqual(base.write_chunk(fp, chunk), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), chunk)

            # With extension:
            key = random_id()
            value = random_id()
            total = size + len('{:x};{}={}'.format(size, key, value)) + 4
            fp = io.BytesIO()
            chunk = ((key, value), data)
            self.assertEqual(base.write_chunk(fp, chunk), total)
            fp.seek(0)
            self.assertEqual(base.read_chunk(fp), chunk)

        # Make sure we can round-trip MAX_CHUNK_SIZE:
        size = base.MAX_CHUNK_SIZE
        data = os.urandom(size)
        total = size + len('{:x}'.format(size)) + 4
        fp = io.BytesIO()
        chunk = (None, data)
        self.assertEqual(base.write_chunk(fp, chunk), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), chunk)

        # With extension:
        key = random_id()
        value = random_id()
        total = size + len('{:x};{}={}'.format(size, key, value)) + 4
        chunk = ((key, value), data)
        fp = io.BytesIO()
        self.assertEqual(base.write_chunk(fp, chunk), total)
        fp.seek(0)
        self.assertEqual(base.read_chunk(fp), chunk)


class BodyBackendTestCase(BackendTestCase):
    @property
    def BODY_READY(self):
        return self.getattr('BODY_READY')

    @property
    def BODY_STARTED(self):
        return self.getattr('BODY_STARTED')

    @property
    def BODY_CONSUMED(self):
        return self.getattr('BODY_CONSUMED')

    @property
    def BODY_ERROR(self):
        return self.getattr('BODY_ERROR')

    @property
    def MAX_IO_SIZE(self):
        return self.getattr('MAX_IO_SIZE')

    @property
    def Reader(self):
        return self.getattr('Reader')

    @property
    def Writer(self):
        return self.getattr('Writer')



class TestBody_Py(BodyBackendTestCase):
    @property
    def Body(self):
        return self.getattr('Body')

    def test_init(self):
        Body = self.Body
        rfile = io.BytesIO()

        # Bad content_length type:
        with self.assertRaises(TypeError) as cm:
            Body(rfile, 17.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, float, 17.0)
        )
        with self.assertRaises(TypeError) as cm:
            Body(rfile, '17')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('content_length', int, str, '17')
        )

        # Bad content_length value:
        max_uint64 = 2**64 - 1
        max_length = 9999999999999999
        for bad in (-max_uint64, -max_length, -17, -1, max_length + 1, max_uint64 + 1):
            with self.assertRaises(ValueError) as cm:
                Body(rfile, bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= content_length <= 9999999999999999; got {!r}'.format(bad)
            )

        # All good:
        for good in (0, 1, 17, 34969, max_length):
            body = Body(rfile, good)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertIs(body.rfile, rfile)
            self.assertEqual(body.content_length, good)
            self.assertEqual(repr(body), 'Body(<rfile>, {!r})'.format(good))

        # Body.closed should be read-only:
        with self.assertRaises(AttributeError) as cm:
            body.state = 1
        if self.backend is _basepy:
            self.assertEqual(str(cm.exception), "can't set attribute")
        else:
            self.assertEqual(str(cm.exception), 'readonly attribute')
        self.assertEqual(body.state, self.BODY_READY)

    def test_read(self):
        Body = self.Body
        data = os.urandom(1776)
        rfile = io.BytesIO(data)
        body = Body(rfile, len(data))

        # Bad size type:
        with self.assertRaises(TypeError) as cm:
            body.read(18.0)
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, float, 18.0)
        )
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)
        with self.assertRaises(TypeError) as cm:
            body.read('18')
        self.assertEqual(str(cm.exception),
            base._TYPE_ERROR.format('size', int, str, '18')
        )
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 1776)

        # size < 0 or size > MAX_READ_SIZE
        toobig = base.MAX_READ_SIZE + 1
        for bad in (-18, -1, toobig):
            body = Body(rfile, 1776)
            with self.assertRaises(ValueError) as cm:
                body.read(bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= {}; got {}'.format(base.MAX_READ_SIZE, bad)
            )
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(rfile.tell(), 0)
            self.assertEqual(body.content_length, 1776)

            body = Body(rfile, toobig)
            with self.assertRaises(ValueError) as cm:
                body.read(bad)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= {}; got {}'.format(base.MAX_READ_SIZE, bad)
            )
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(rfile.tell(), 0)
            self.assertEqual(body.content_length, toobig)

        # Test when read size > MAX_READ_SIZE:
        rfile = io.BytesIO()
        body = Body(rfile, toobig)
        self.assertEqual(body.content_length, toobig)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'would exceed max read size: 16777217 > 16777216'
        )
        body = Body(rfile, toobig)
        self.assertEqual(body.content_length, toobig)
        with self.assertRaises(ValueError) as cm:
            body.read(None)
        self.assertEqual(str(cm.exception),
            'would exceed max read size: 16777217 > 16777216'
        )

        # Now read it all at once:
        rfile = io.BytesIO(data)
        body = Body(rfile, len(data))
        self.assertEqual(body.read(), data)
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # Read it again, this time in parts:
        rfile = io.BytesIO(data)
        body = Body(rfile, 1776)
        self.assertEqual(body.read(17), data[0:17])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(18), data[17:35])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 35)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(1741), data[35:])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)

        self.assertEqual(body.read(1776), b'')
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(body.content_length, 1776)

        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # ValueError (underflow) when trying to read all:
        rfile = io.BytesIO(data)
        body = Body(rfile, 1800)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1800')
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # ValueError (underflow) error when read in parts:
        data = os.urandom(35)
        rfile = io.BytesIO(data)
        body = Body(rfile, 37)
        self.assertEqual(body.read(18), data[:18])
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(rfile.tell(), 18)
        self.assertEqual(body.content_length, 37)
        with self.assertRaises(ValueError) as cm:
            body.read(19)
        self.assertEqual(str(cm.exception), 'underflow: 17 < 19')
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # Test with empty body:
        rfile = io.BytesIO(os.urandom(21))
        body = Body(rfile, 0)
        self.assertEqual(body.read(17), b'')
        self.assertIs(body.chunked, False)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(body.content_length, 0)
        with self.assertRaises(ValueError) as cm:
            body.read(17)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )

        # Test with random chunks:
        for i in range(25):
            chunks = random_chunks()
            assert chunks[-1] == b''
            data = b''.join(chunks)
            trailer = os.urandom(17)
            rfile = io.BytesIO(data + trailer)
            body = Body(rfile, len(data))
            for chunk in chunks:
                self.assertEqual(body.read(len(chunk)), chunk)
            self.assertIs(body.chunked, False)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), len(data))
            self.assertEqual(body.content_length, len(data))
            with self.assertRaises(ValueError) as cm:
                body.read(17)
            self.assertEqual(str(cm.exception),
                'Body.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(rfile.read(), trailer)

    def test_iter(self):
        Body = self.Body
        data = os.urandom(1776)

        # content_length=0
        rfile = io.BytesIO(data)
        body = Body(rfile, 0)
        self.assertEqual(list(body), [])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 0)
        self.assertEqual(rfile.read(), data)

        # content_length=69
        rfile = io.BytesIO(data)
        body = Body(rfile, 69)
        self.assertEqual(list(body), [data[:69]])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 69)
        self.assertEqual(rfile.read(), data[69:])

        # content_length=1776
        rfile = io.BytesIO(data)
        body = Body(rfile, 1776)
        self.assertEqual(list(body), [data])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), 1776)
        self.assertEqual(rfile.read(), b'')

        # content_length=1777
        rfile = io.BytesIO(data)
        body = Body(rfile, 1777)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1777')
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

        # Make sure data is read in IO_SIZE chunks:
        data1 = os.urandom(base.IO_SIZE)
        data2 = os.urandom(base.IO_SIZE)
        length = base.IO_SIZE * 2
        rfile = io.BytesIO(data1 + data2)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with smaller final chunk:
        length = base.IO_SIZE * 2 + len(data)
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), b'')

        # Again, with length 1 byte less than available:
        length = base.IO_SIZE * 2 + len(data) - 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        self.assertEqual(list(body), [data1, data2, data[:-1]])
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(rfile.tell(), length)
        self.assertEqual(rfile.read(), data[-1:])

        # Again, with length 1 byte *more* than available:
        length = base.IO_SIZE * 2 + len(data) + 1
        rfile = io.BytesIO(data1 + data2 + data)
        body = Body(rfile, length)
        with self.assertRaises(ValueError) as cm:
            list(body)
        self.assertEqual(str(cm.exception), 'underflow: 1776 < 1777')
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'Body.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertIs(rfile.closed, False)

    def test_write_to(self):
        Body = self.Body
        data1 = os.urandom(17)
        data2 = os.urandom(19)
        rfile = io.BytesIO(data1 + data2)
        wfile = io.BytesIO()
        body = Body(rfile, 17)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.write_to(wfile), 17)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), 17)
        self.assertEqual(wfile.tell(), 17)
        self.assertEqual(rfile.read(), data2)
        self.assertEqual(wfile.getvalue(), data1)

class TestBody_C(TestBody_Py):
    backend = _base


class TestChunkedBody_Py(BodyBackendTestCase):
    @property
    def ChunkedBody(self):
        return self.getattr('ChunkedBody')

    @property
    def Reader(self):
        return self.getattr('Reader')

    def check_common(self, body, rfile):
        if self.backend is _basepy:
            setmsg = "can't set attribute"
            delmsg = "can't delete attribute"
            setmsg2 = "'ChunkedBody' object attribute 'chunked' is read-only"
            delmsg2 = setmsg2
        else:
            setmsg = 'readonly attribute'
            delmsg =  setmsg
            setmsg2 = setmsg
            delmsg2 = delmsg
        members = ('rfile', 'fastpath', 'state')

        # Test everything except body.chunked:
        for name in members:  
            with self.assertRaises(AttributeError) as cm:
                setattr(body, name, True)
            self.assertEqual(str(cm.exception), setmsg)
            with self.assertRaises(AttributeError) as cm:
                delattr(body, name)
            self.assertEqual(str(cm.exception), delmsg)

        # Test body.chunked:
        with self.assertRaises(AttributeError) as cm:
            body.chunked = False
        self.assertEqual(str(cm.exception), setmsg2)
        with self.assertRaises(AttributeError) as cm:
            del body.chunked
        self.assertEqual(str(cm.exception), delmsg2)

        self.assertIs(body.rfile, rfile)
        self.assertIs(body.chunked, True)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(repr(body), 'ChunkedBody(<rfile>)')

    def iter_rfiles(self, data):
        yield io.BytesIO(data)
        yield self.Reader(MockSocket(data, None), base.bodies)
        yield self.Reader(MockSocket(data, 1), base.bodies)
        yield self.Reader(MockSocket(data, 2), base.bodies)

    def test_init(self):
        # Test with backend.Reader:
        sock = MockSocket(b'', None)
        rfile = self.Reader(sock, base.bodies)
        self.assertEqual(sys.getrefcount(rfile), 2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 3)
        self.assertIs(body.fastpath, True)
        self.check_common(body, rfile)
        self.assertEqual(sys.getrefcount(rfile), 3)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Test with arbitrary file-like object:
        rfile = io.BytesIO()
        self.assertEqual(sys.getrefcount(rfile), 2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertIs(body.fastpath, False)
        self.check_common(body, rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.Reader, rfile.readline missing:
        class MissingReadline:
            def read(self, size=None):
                assert False
        rfile = MissingReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingReadline' object has no attribute 'readline'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.Reader, rfile.readline() not callable:
        class BadReadline:
            readline = 'hello'
            def read(self, size=None):
                assert False
        rfile = BadReadline()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception), 'rfile.readline() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.Reader, rfile.read missing:
        class MissingRead:
            def readline(self, size):
                assert False
        rfile = MissingRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(AttributeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception),
            "'MissingRead' object has no attribute 'read'"
        )
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Not a backend.Reader, rfile.read() not callable:
        class BadRead:
            read = 'hello'
            def readline(self, size):
                assert False
        rfile = BadRead()
        self.assertEqual(sys.getrefcount(rfile), 2)
        with self.assertRaises(TypeError) as cm:
            self.ChunkedBody(rfile)
        self.assertEqual(str(cm.exception), 'rfile.read() is not callable')
        self.assertEqual(sys.getrefcount(rfile), 2)

    def test_repr(self):
        data = b'c\r\nhello, world\r\n0;k=v\r\n\r\n'
        for rfile in self.iter_rfiles(data):
            self.assertEqual(sys.getrefcount(rfile), 2)
            body = self.ChunkedBody(rfile)
            refcount = (3 if type(rfile) is self.Reader else 5)
            self.assertEqual(sys.getrefcount(rfile), refcount)
            self.assertEqual(repr(body), 'ChunkedBody(<rfile>)')
            self.assertEqual(sys.getrefcount(rfile), refcount)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

    def test_readchunk(self):
        rfile = io.BytesIO(b'0\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (None, b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'0;key=value\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (('key', 'value'), b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c\r\nhello, world\r\n0;k=v\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (None, b'hello, world'))
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(body.readchunk(), (('k', 'v'), b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(b'c;key=value\r\nhello, world\r\n0\r\n\r\n')
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        self.assertEqual(body.readchunk(), (('key', 'value'), b'hello, world'))
        self.assertEqual(body.state, self.BODY_STARTED)
        self.assertEqual(body.readchunk(), (None, b''))
        self.assertEqual(body.state, self.BODY_CONSUMED)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        good1 = b'c;k=v\r\n'
        good2 = b'hello, world\r\n'

        class MockFile:
            def __init__(self, ret1, ret2):
                self.__ret1 = ret1
                self.__ret2 = ret2
            
            def readline(self, size):
                assert type(size) is int and size == 4096
                return self.__ret1

            def read(self, size):
                assert type(size) is int and size == 14
                return self.__ret2

        # readline() dosen't return bytes:
        rfile = MockFile(bytearray(good1), good2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(TypeError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'need a {!r}; readline() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() returns to many bytes
        bad1 = os.urandom(4097)
        rfile = MockFile(bad1, good2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'readline() returned too many bytes: 4097 > 4096'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # readline() returns bytes, but it doesn't contain a b'\r\n':
        for bad1 in (b'', b'\n', b'\rc\n', b'c\rhello, world', b'c\nhello, world'):
            rfile = MockFile(bad1, good2)
            body = self.ChunkedBody(rfile)
            self.assertEqual(sys.getrefcount(rfile), 5)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad1)
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(rfile), 5)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        # read() dosen't return bytes:
        rfile = MockFile(good1, bytearray(good2))
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(TypeError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'need a {!r}; read() returned a {!r}'.format(bytes, bytearray)
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # read() doesn't return the correct amount of data:
        for bad2 in (b'', b'hello world\r\n', os.urandom(13), os.urandom(15)):
            rfile = MockFile(good1, bad2)
            body = self.ChunkedBody(rfile)
            self.assertEqual(sys.getrefcount(rfile), 5)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'read() returned {} bytes, need 14'.format(len(bad2))
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(rfile), 5)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        # data isn't correctly terminated:
        bad2 = (b'\r\n' * 6) + b'Az'
        assert len(bad2) == 14
        rfile = MockFile(good1, bad2)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 5)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception), "bad chunk data termination: b'Az'")
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 5)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        # Now test internal Reader fast-path:
        for bad in (b'', b'\rc\n', b'c\rhello, world', b'c\nhello, world'):
            sock = MockSocket(bad, None)
            rfile = self.Reader(sock, base.bodies)
            body = self.ChunkedBody(rfile)
            self.assertEqual(sys.getrefcount(rfile), 3)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad)
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            with self.assertRaises(ValueError) as cm:
                body.readchunk()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_ERROR, cannot be used'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(rfile), 3)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        sock = MockSocket(b'c\r\nhello, worl\r\n', None)
        rfile = self.Reader(sock, base.bodies)
        body = self.ChunkedBody(rfile)
        self.assertEqual(sys.getrefcount(rfile), 3)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),'underflow: 13 < 14')
        self.assertEqual(body.state, self.BODY_ERROR)
        with self.assertRaises(ValueError) as cm:
            body.readchunk()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertEqual(sys.getrefcount(rfile), 3)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        for i in range(1, 5):
            chunks = random_chunks2(i)
            wfile = io.BytesIO()
            for chunk in chunks:
                base.write_chunk(wfile, chunk)
            data = wfile.getvalue()
            del wfile

            for rfile in self.iter_rfiles(data):
                body = self.ChunkedBody(rfile)
                refcount = (3 if type(rfile) is self.Reader else 5)
                self.assertEqual(body.state, self.BODY_READY)
                for (j, chunk) in enumerate(chunks):
                    if j == 0:
                        self.assertEqual(body.state, self.BODY_READY)
                    else:
                        self.assertEqual(body.state, self.BODY_STARTED)
                    self.assertEqual(body.readchunk(), chunk)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                with self.assertRaises(ValueError) as cm:
                    body.readchunk()
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertEqual(sys.getrefcount(rfile), refcount)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            for rfile in self.iter_rfiles(data):
                body = self.ChunkedBody(rfile)
                refcount = (3 if type(rfile) is self.Reader else 5)
                body = self.ChunkedBody(rfile)
                result = tuple(body)
                self.assertEqual(len(result), len(chunks))
                self.assertEqual(result, chunks)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                with self.assertRaises(ValueError) as cm:
                    tuple(body)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertEqual(sys.getrefcount(rfile), refcount)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

    def test_read(self):
        for i in range(1, 10):
            chunks = random_chunks2(i)
            data = b''.join(c[1] for c in chunks)
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks:
                total += base.write_chunk(wfile, chunk)
            cdata = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(cdata), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile

            rfile = io.BytesIO(cdata)
            body = self.ChunkedBody(rfile)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(body.read(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), total)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

            rfile = io.BytesIO(cdata)
            body = self.ChunkedBody(rfile)
            self.assertEqual(body.state, self.BODY_READY)
            self.assertEqual(body.read(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(rfile.tell(), total)
            with self.assertRaises(ValueError) as cm:
                body.read()
            self.assertEqual(str(cm.exception),
                'ChunkedBody.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(body.state, self.BODY_CONSUMED)
            del body
            self.assertEqual(sys.getrefcount(rfile), 2)

        chunks = tuple(random_chunk(self.MAX_IO_SIZE // 8) for i in range(8))
        one = random_chunk(1)
        empty = random_chunk(0)

        goodchunks = chunks + (empty,)
        data = b''.join(c[1] for c in goodchunks)
        self.assertEqual(len(data), self.MAX_IO_SIZE)
        wfile = io.BytesIO()
        total = 0
        for good in goodchunks:
            total += base.write_chunk(wfile, good)
        cdata = wfile.getvalue()
        self.assertEqual(wfile.tell(), total)
        self.assertEqual(len(cdata), total)
        self.assertEqual(sys.getrefcount(wfile), 2)
        del wfile

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.read(), data)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), total)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(body.read(), data)
        self.assertEqual(body.state, self.BODY_CONSUMED)
        self.assertEqual(rfile.tell(), total)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_CONSUMED, already consumed'
        )
        self.assertEqual(body.state, self.BODY_CONSUMED)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        badchunks = (one,) + chunks + (empty,)
        data = b''.join(c[1] for c in badchunks)
        wfile = io.BytesIO()
        total = 0
        for bad in badchunks:
            total += base.write_chunk(wfile, bad)
        cdata = wfile.getvalue()
        self.assertEqual(wfile.tell(), total)
        self.assertEqual(len(cdata), total)
        self.assertEqual(sys.getrefcount(wfile), 2)
        del wfile

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'chunks exceed MAX_IO_SIZE: {} > {}'.format(
                self.MAX_IO_SIZE + 1, self.MAX_IO_SIZE
            )
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

        rfile = io.BytesIO(cdata)
        body = self.ChunkedBody(rfile)
        self.assertEqual(body.state, self.BODY_READY)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'chunks exceed MAX_IO_SIZE: {} > {}'.format(
                self.MAX_IO_SIZE + 1, self.MAX_IO_SIZE
            )
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        with self.assertRaises(ValueError) as cm:
            body.read()
        self.assertEqual(str(cm.exception),
            'ChunkedBody.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)
        self.assertLess(rfile.tell(), total - 4)
        del body
        self.assertEqual(sys.getrefcount(rfile), 2)

    def get_rfile_plus_body(self, data, mock=False, rcvbuf=None):
        rfile = io.BytesIO(data)
        if mock is True:
            obj = self.Reader(MockSocket2(rfile, rcvbuf), base.bodies)
        else:
            assert mock is False
            obj = rfile
        return (data, rfile, self.ChunkedBody(obj))

    def iter_bodies(self, data, extra):
        for d in (data, data + extra):
            yield self.get_rfile_plus_body(d)
            yield self.get_rfile_plus_body(d, mock=True)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=1)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=2)
            yield self.get_rfile_plus_body(d, mock=True, rcvbuf=3)

    def test_write_to(self):
        extra = os.urandom(1776)
        for count in range(1, 10):
            chunks = random_chunks2(count)
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks:
                total += base.write_chunk(wfile, chunk)
            data = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(data), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile

            # Normal use-case:
            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                self.assertEqual(body.state, self.BODY_READY)
                self.assertEqual(body.write_to(wfile), total)
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertGreaterEqual(rfile.tell(), total)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Consume, then try again:
            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                self.assertEqual(body.state, self.BODY_READY)
                self.assertEqual(body.write_to(wfile), total)
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_CONSUMED)
                self.assertGreaterEqual(rfile.tell(), total)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_CONSUMED, already consumed'
                )
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Use ChunkedBody.readchunk(), then ChunkedBody.write_to()
            for (d, rfile, body) in self.iter_bodies(data, extra):
                self.assertEqual(body.readchunk(), chunks[0])
                if len(chunks) == 1:
                    self.assertEqual(body.state, self.BODY_CONSUMED)
                else:
                    self.assertEqual(body.state, self.BODY_STARTED)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                if len(chunks) == 1:
                    self.assertEqual(str(cm.exception),
                        'ChunkedBody.state == BODY_CONSUMED, already consumed'
                    )
                    self.assertEqual(body.state, self.BODY_CONSUMED)
                else:
                    self.assertEqual(str(cm.exception),
                        'ChunkedBody.state == BODY_STARTED, cannot start another operation'
                    )
                    self.assertEqual(body.state, self.BODY_STARTED)
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')
                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

            # Missing the termintating empty chunk data:
            extra = b'ABCDE' * 4096
            wfile = io.BytesIO()
            total = 0
            for chunk in chunks[:-1]:
                total += base.write_chunk(wfile, chunk)
            data = wfile.getvalue()
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(len(data), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del wfile            

            for (d, rfile, body) in self.iter_bodies(data, extra):
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)            
                self.assertEqual(str(cm.exception),
                    '{!r} not found in {!r}...'.format(
                        b'\r\n', d[total:total+32]
                    )
                )
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_ERROR)
                self.assertEqual(wfile.tell(), total)
                self.assertEqual(wfile.getvalue(), data)

                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'ChunkedBody.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(sys.getrefcount(wfile), 2)
                self.assertEqual(body.state, self.BODY_ERROR)
                self.assertEqual(wfile.tell(), 0)
                self.assertEqual(wfile.getvalue(), b'')

                del body
                self.assertEqual(sys.getrefcount(rfile), 2)

class TestChunkedBody_C(TestChunkedBody_Py):
    backend = _base


def get_source_refcounts(source):
    counts = {'': sys.getrefcount(source)}
    for i in range(len(source)):
        base = str(i)
        counts[base] = sys.getrefcount(source[i])
        # Note, it's problematic to check refcounts on None, in both the 
        # Python and C implementations.
        if source[i][0] is not None:
            counts[base + '.ext'] = sys.getrefcount(source[i][0])
            counts[base + '.ext.key'] = sys.getrefcount(source[i][0][0])
            counts[base + '.ext.val'] = sys.getrefcount(source[i][0][1])
        counts[base + '.data'] = sys.getrefcount(source[i][1])
    return counts


def iter_body_sources():
    for count in range(10):
        yield tuple(random_data() for i in range(count))
        source = [random_data() for i in range(count)]
        source.extend([b'' for i in range(3)])
        random.shuffle(source)
        yield tuple(source)


class TestBodyIter_Py(BodyBackendTestCase):
    @property
    def BodyIter(self):
        return self.getattr('BodyIter')

    def test_init(self):
        source = tuple(random_data() for i in range(5))
        content_length = sum(len(part) for part in source)
        self.assertEqual(sys.getrefcount(source), 2)
        body = self.BodyIter(source, content_length)
        self.assertEqual(sys.getrefcount(source), 3)
        self.assertIs(body.source, source)
        self.assertEqual(body.content_length, content_length)
        self.assertEqual(body.state, self.BODY_READY)
        self.assertEqual(repr(body),
            'BodyIter(<source>, {})'.format(content_length)
        )
        self.assertEqual(sys.getrefcount(source), 3)
        del body
        self.assertEqual(sys.getrefcount(source), 2)

    def test_write_to(self):
        class BadFile:
            def __init__(self, sizes):
                assert type(sizes) is list
                self.__sizes = sizes

            def write(self, buf):
                ret = self.__sizes.pop(0)
                if isinstance(ret, Exception):
                    raise ret
                return ret

        if self.backend is _basepy:
            msg = 'memoryview: NoneType object does not have the buffer interface'
        else:
            msg = "'NoneType' does not support the buffer interface"

        body = self.BodyIter(None, 17)
        wfile = io.BytesIO()
        with self.assertRaises(TypeError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception), "'NoneType' object is not iterable")
        self.assertEqual(body.state, self.BODY_ERROR)
        wfile = io.BytesIO()
        with self.assertRaises(ValueError) as cm:
            body.write_to(wfile)
        self.assertEqual(str(cm.exception),
            'BodyIter.state == BODY_ERROR, cannot be used'
        )
        self.assertEqual(body.state, self.BODY_ERROR)

        for source in iter_body_sources():
            total = sum(len(part) for part in source)
            data = b''.join(source)

            body = self.BodyIter(source, total)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(source), 2)

            body = self.BodyIter(source, total)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), data)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'BodyIter.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(wfile.tell(), 0)
            self.assertEqual(wfile.getvalue(), b'')
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(source), 2)

            sizes = tuple(filter(None, (len(part) for part in source)))
            marker1 = random_id()
            marker2 = random_id()
            exc1 = Exception(marker1)
            exc2 = ValueError(marker2)
            for (i, s) in enumerate(sizes):
                for offset in [-2, -1, 1, 2]:
                    bad = list(sizes)
                    bad[i] += offset
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'need wrote == {}; got {}'.format(s, s + offset)
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

                for b in (str(s), float(s), None):
                    bad = list(sizes)
                    bad[i] = b
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(TypeError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        TYPE_ERROR.format('wrote', int, type(b), b)
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

                for exc in (exc1, exc2):
                    bad = list(sizes)
                    bad[i] = exc
                    wfile = BadFile(bad)
                    body = self.BodyIter(source, total)
                    with self.assertRaises(type(exc)) as cm:
                        body.write_to(wfile)
                    self.assertIs(cm.exception, exc)
                    self.assertEqual(str(cm.exception), str(exc))
                    self.assertEqual(body.state, self.BODY_ERROR)
                    wfile = io.BytesIO()
                    with self.assertRaises(ValueError) as cm:
                        body.write_to(wfile)
                    self.assertEqual(str(cm.exception),
                        'BodyIter.state == BODY_ERROR, cannot be used'
                    )
                    self.assertEqual(body.state, self.BODY_ERROR)

            if total != 0:
                wfile = io.BytesIO()
                body = self.BodyIter(source, total - 1)
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'exceeds content_length: {} > {}'.format(total, total - 1)
                )
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

            for n in (1, 2, 3):
                wfile = io.BytesIO()
                body = self.BodyIter(source, total + n)
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'deceeds content_length: {} < {}'.format(total, total + n)
                )
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

            for i in range(len(source)):
                badsource = list(source)
                badsource[i] = None
                wfile = io.BytesIO()
                body = self.BodyIter(badsource, total)
                with self.assertRaises(TypeError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception), msg)
                self.assertEqual(body.state, self.BODY_ERROR)
                wfile = io.BytesIO()
                with self.assertRaises(ValueError) as cm:
                    body.write_to(wfile)
                self.assertEqual(str(cm.exception),
                    'BodyIter.state == BODY_ERROR, cannot be used'
                )
                self.assertEqual(body.state, self.BODY_ERROR)

class TestBodyIter_C(TestBodyIter_Py):
    backend = _base



class TestChunkedBodyIter_Py(BackendTestCase):
    @property
    def ChunkedBodyIter(self):
        return self.getattr('ChunkedBodyIter')

    @property
    def ChunkedBody(self):
        return self.getattr('ChunkedBody')

    @property
    def Writer(self):
        return self.getattr('Writer')

    @property
    def BODY_READY(self):
        return self.getattr('BODY_READY')

    @property
    def BODY_CONSUMED(self):
        return self.getattr('BODY_CONSUMED')

    @property
    def BODY_ERROR(self):
        return self.getattr('BODY_ERROR')

    def test_init(self):
        source = random_chunks2()
        self.assertEqual(sys.getrefcount(source), 2)
        body = self.ChunkedBodyIter(source)
        self.assertEqual(sys.getrefcount(source), 3)
        self.assertIs(body.source, source)
        self.assertEqual(body.state, 0)
        self.assertEqual(repr(body), 'ChunkedBodyIter(<source>)')
        self.assertEqual(sys.getrefcount(source), 3)
        del body
        self.assertEqual(sys.getrefcount(source), 2)

    def test_write_to(self):
        ext = ('k', 'v')
        pairs = (
            (
                (
                    (None, b''),
                ),
                b'0\r\n\r\n',
            ),
            (
                (
                    (ext, b''),
                ),
                b'0;k=v\r\n\r\n',
            ),
            (
                (
                    (ext, b'hello, world'),
                    (None, b''),
                ),
                b'c;k=v\r\nhello, world\r\n0\r\n\r\n',
            ),
            (
                (
                    (None, b'hello, world'),
                    (ext, b''),
                ),
                b'c\r\nhello, world\r\n0;k=v\r\n\r\n',
            ),
        )
        for (source, result) in pairs:
            counts = get_source_refcounts(source)
            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), len(result))
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(wfile.getvalue(), result)
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2) 
            self.assertEqual(get_source_refcounts(source), counts)

        for n in range(1, 10):
            source = random_chunks2(n)
            counts = get_source_refcounts(source)

            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            total = body.write_to(wfile)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertIs(type(total), int)
            self.assertGreater(total, 4)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(sys.getrefcount(wfile), 2)
            result = wfile.getvalue()
            del body
            self.assertEqual(sys.getrefcount(wfile), 2) 
            self.assertEqual(get_source_refcounts(source), counts)

            rfile = io.BytesIO(result)
            rbody = self.ChunkedBody(rfile)
            self.assertEqual(tuple(rbody), source)
            self.assertEqual(rfile.tell(), total)

            body = self.ChunkedBodyIter(source)
            wfile = io.BytesIO()
            self.assertEqual(body.write_to(wfile), total)
            self.assertEqual(body.state, self.BODY_CONSUMED)
            self.assertEqual(wfile.tell(), total)
            self.assertEqual(wfile.getvalue(), result)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_CONSUMED, already consumed'
            )
            self.assertEqual(body.state, self.BODY_CONSUMED)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2) 
            self.assertEqual(get_source_refcounts(source), counts)

            # no chunks, or final chunk is not empty:
            bad = list(source)
            del bad[-1]
            bad = tuple(bad)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'final chunk data was not empty'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertTrue(result.startswith(wfile.getvalue()))
            self.assertEqual(sys.getrefcount(wfile), 2)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'final chunk data was not empty'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertTrue(result.startswith(wfile.getvalue()))
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_ERROR, cannot be used'
            )
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)
            del bad
            self.assertEqual(get_source_refcounts(source), counts)

            # additional chunk after an empty chunk:
            bad = list(source)
            bad.append(random_chunk(0))
            random.shuffle(bad)
            bad = tuple(bad)
            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'additional chunk after empty chunk data'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(wfile), 2)
            self.assertGreater(wfile.tell(), 4)
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)

            body = self.ChunkedBodyIter(bad)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'additional chunk after empty chunk data'
            )
            self.assertEqual(body.state, self.BODY_ERROR)
            self.assertEqual(sys.getrefcount(wfile), 2)
            wfile = io.BytesIO()
            with self.assertRaises(ValueError) as cm:
                body.write_to(wfile)
            self.assertEqual(str(cm.exception),
                'ChunkedBodyIter.state == BODY_ERROR, cannot be used'
            )
            del body
            self.assertEqual(sys.getrefcount(wfile), 2)

            del bad
            self.assertEqual(get_source_refcounts(source), counts)


class TestChunkedBodyIter_C(TestChunkedBodyIter_Py):
    backend = _base


class BadSocket:
    def __init__(self, ret):
        self._ret = ret

    def shutdown(self, how):
        pass

    def recv_into(self, buf):
        if isinstance(self._ret, Exception):
            raise self._ret
        return self._ret


class TestReader_Py(BackendTestCase):
    @property
    def Reader(self):
        return self.getattr('Reader')

    @property
    def Range(self):
        return self.getattr('Range')

    @property
    def MIN_PREAMBLE(self):
        return self.backend.MIN_PREAMBLE

    @property
    def DEFAULT_PREAMBLE(self):
        return self.backend.DEFAULT_PREAMBLE

    @property
    def MAX_PREAMBLE(self):
        return self.backend.MAX_PREAMBLE

    @property
    def ResponseType(self):
        return self.backend.ResponseType

    @property
    def EmptyPreambleError(self):
        return self.backend.EmptyPreambleError

    def new(self, data=b'', rcvbuf=None):
        sock = MockSocket(data, rcvbuf)
        reader = self.Reader(sock, base.bodies)
        return (sock, reader)

    def test_init(self):
        default = self.DEFAULT_PREAMBLE
        _min = self.MIN_PREAMBLE
        _max = self.MAX_PREAMBLE
        self.assertTrue(_min <= default <= _max)

        sock = MockSocket(b'')
        reader = self.Reader(sock, base.bodies)
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # Test min and max sizes:
        for good in (_min, _max):
            reader = self.Reader(sock, base.bodies, size=good)
            self.assertEqual(reader.expose(), b'\x00' * good)

        # size out of range:
        for bad in (_min - 1, _max + 1):
            with self.assertRaises(ValueError) as cm:
                self.Reader(sock, base.bodies, size=bad)
            self.assertEqual(str(cm.exception),
                'need {} <= size <= {}; got {}'.format(_min, _max, bad)
            )

    def test_del(self):
        sock = MockSocket(b'')
        self.assertEqual(sys.getrefcount(sock), 2)
        bodies = base.bodies
        c1 = sys.getrefcount(bodies)
        c2 = sys.getrefcount(bodies.Body)
        c3 = sys.getrefcount(bodies.ChunkedBody)
        reader = self.Reader(sock, bodies)
        self.assertEqual(sys.getrefcount(sock), 3)
        self.assertEqual(sys.getrefcount(bodies), c1)
        self.assertEqual(sys.getrefcount(bodies.Body), c2 + 1)
        self.assertEqual(sys.getrefcount(bodies.ChunkedBody), c3 + 1)
        del reader
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(bodies), c1)
        self.assertEqual(sys.getrefcount(bodies.Body), c2)
        self.assertEqual(sys.getrefcount(bodies.ChunkedBody), c3)

    def test_read_until(self):
        default = self.DEFAULT_PREAMBLE
        end = b'\r\n'

        data = os.urandom(2 * default)
        (sock, reader) = self.new(data)

        # len(end) == 0:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(4096, b'')
        self.assertEqual(str(cm.exception), 'end cannot be empty')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < 0:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(-1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got -1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < 1:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(0, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 0'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size < len(end):
        with self.assertRaises(ValueError) as cm:
            reader.read_until(1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got 1'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)
        with self.assertRaises(ValueError) as cm:
            reader.read_until(15, os.urandom(16))
        self.assertEqual(str(cm.exception),
            'need 16 <= size <= {}; got 15'.format(default)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # size > default:
        with self.assertRaises(ValueError) as cm:
            reader.read_until(default + 1, end)
        self.assertEqual(str(cm.exception),
            'need 2 <= size <= {}; got {}'.format(default, default + 1)
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(reader.expose(), b'\x00' * default)

        # No data:
        (sock, reader) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(4096, end), b'')
        self.assertEqual(sock._recv_into_calls, 1)

        (sock, reader) = self.new()
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(4096, end, readline=True), b'')
        self.assertEqual(sock._recv_into_calls, 1)

        # Main event:
        part1 = os.urandom(1234)
        part2 = os.urandom(2345)
        end = os.urandom(16)
        data = part1 + end + part2 + end
        size = len(data)

        # readline kwarg not provided:
        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(size, end), part1)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(reader.read_until(size, end), part2)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        # readline=False:
        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(reader.read_until(size, end, readline=False), part1)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(reader.read_until(size, end, readline=False), part2)
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        # readline=True:
        (sock, reader) = self.new(data)
        self.assertIsNone(sock._rcvbuf)
        self.assertEqual(
            reader.read_until(size, end, readline=True),
            part1 + end
        )
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), part2 + end)
        self.assertEqual(
            reader.read_until(size, end, readline=True),
            part2 + end
        )
        self.assertEqual(sock._recv_into_calls, 1)
        self.assertEqual(reader.peek(-1), b'')

        nope = os.urandom(16)
        marker = os.urandom(16)
        suffix = os.urandom(666)
        for i in range(318):
            prefix = os.urandom(i)
            data = prefix + marker
            total_data = data + suffix

            # readline=False, found:
            (sock, reader) = self.new(total_data, 333)
            self.assertEqual(reader.read_until(333, marker), prefix)
            self.assertEqual(reader.peek(-1), total_data[i+16:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), i + 16)

            # readline=False, not found:
            (sock, reader) = self.new(total_data, 333)
            with self.assertRaises(ValueError) as cm:
                reader.read_until(333, nope)
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(nope, total_data[:32])
            )
            self.assertEqual(reader.peek(-1), total_data[:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), 0)
            self.assertEqual(reader.read_until(333, marker), prefix)
            self.assertEqual(reader.peek(-1), total_data[i+16:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), i + 16)

            # readline=True, found:
            (sock, reader) = self.new(total_data, 333)
            self.assertEqual(reader.read_until(333, marker, True), data)
            self.assertEqual(reader.peek(-1), total_data[i+16:333])
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), i + 16)

            # readline=True, not found:
            (sock, reader) = self.new(total_data, 333)
            self.assertEqual(reader.read_until(333, nope, True),
                total_data[:333]
            )
            self.assertEqual(reader.peek(-1), b'')
            self.assertEqual(reader.rawtell(), 333)
            self.assertEqual(reader.tell(), 333)

    def test_readline(self):
        size = self.DEFAULT_PREAMBLE
        (sock, reader) = self.new()
        self.assertEqual(reader.readline(size), b'')
        data = b'D' * size
        (sock, reader) = self.new(data)
        self.assertEqual(reader.readline(size), data)

    def test_readchunk(self):
        (sock, reader) = self.new(b'0\r\n\r\n')
        self.assertEqual(reader.readchunk(),
            (None, b'')
        )
        (sock, reader) = self.new(b'0;key=value\r\n\r\n')
        self.assertEqual(reader.readchunk(),
            (('key', 'value'), b'')
        )
        (sock, reader) = self.new(b'c\r\nhello, world\r\n')
        self.assertEqual(reader.readchunk(),
            (None, b'hello, world')
        )
        (sock, reader) = self.new(b'c;key=value\r\nhello, world\r\n')
        self.assertEqual(reader.readchunk(),
            (('key', 'value'), b'hello, world')
        )

        for bad in (b'', b'0', b'0;key=value', b'c', b'c;key=value'):
            (sock, reader) = self.new(bad)
            with self.assertRaises(ValueError) as cm:
                reader.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', bad)
            )

        badset = tuple(frozenset(range(256)) - frozenset(b'\r\n'))
        base = bytes(random.choice(badset) for i in range(4095))
        for end in (b'\r', b'\n', b'\r\n'):
            (sock, reader) = self.new(base + end)
            with self.assertRaises(ValueError) as cm:
                reader.readchunk()
            self.assertEqual(str(cm.exception),
                '{!r} not found in {!r}...'.format(b'\r\n', base[:32])
            )

    def check_read_request(self, rcvbuf):
        # Empty preamble:
        (sock, reader) = self.new(b'', rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            reader.read_request()
        self.assertEqual(str(cm.exception), 'request preamble is empty')

        # Good preamble termination:
        prefix = b'GET / HTTP/1.1'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        data = prefix + term + suffix
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        request = reader.read_request()
        self.assertIsInstance(request, self.getattr('RequestType'))
        self.assertEqual(request, ('GET', '/', {}, None, [], [], None))

        # Bad preamble termination:
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_request()
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )
            self.assertEqual(reader.rawtell(), len(data))
            self.assertEqual(reader.tell(), 0)

        # Request line too short
        for i in range(len(prefix)):
            bad = bytearray(prefix)
            del bad[i]
            bad = bytes(bad)
            data = bad + term + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_request()
            self.assertEqual(str(cm.exception),
                'request line too short: {!r}'.format(bad)
            )

        # With Range header:
        data = b'GET / HTTP/1.1\r\nRange: bytes=0-0\r\n\r\n'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        request = reader.read_request()
        self.assertIsInstance(request, self.getattr('RequestType'))
        self.assertEqual(request,
            ('GET', '/', {'range': 'bytes=0-0'}, None, [], [], None)
        )
        _range = request.headers['range']
        self.assertIs(type(_range), self.Range)
        self.assertIs(type(_range.start), int)
        self.assertIs(type(_range.stop), int)
        self.assertEqual(_range.start, 0)
        self.assertEqual(_range.stop, 1)
        self.assertEqual(repr(_range), 'Range(0, 1)')
        self.assertEqual(str(_range), 'bytes=0-0')

    def test_read_request(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_request(rcvbuf)

    def check_read_response(self, rcvbuf):
        # Bad method:
        for method in BAD_METHODS:
            (sock, reader) = self.new()
            with self.assertRaises(ValueError) as cm:
                reader.read_response(method)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method)
            )

        # Test when exact b'\r\n\r\n' preamble termination is missing:
        data = b'HTTP/1.1 200 OK\n\r\nhello, world'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        with self.assertRaises(ValueError) as cm:
            reader.read_response('GET')
        self.assertEqual(str(cm.exception),
            '{!r} not found in {!r}...'.format(b'\r\n\r\n', data)
        )
        if rcvbuf is None:
            self.assertEqual(sock._recv_into_calls, 2)
        else:
            self.assertEqual(sock._recv_into_calls, len(data) // rcvbuf + 1)

        prefix = b'HTTP/1.1 200 OK'
        term = b'\r\n\r\n'
        suffix = b'hello, world'
        for bad in BAD_TERM:
            data = prefix + bad + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_response('GET')
            self.assertEqual(str(cm.exception),
                 '{!r} not found in {!r}...'.format(term, data)
            )

        (sock, reader) = self.new(rcvbuf=rcvbuf)
        with self.assertRaises(self.backend.EmptyPreambleError) as cm:
            reader.read_response('GET')
        self.assertEqual(str(cm.exception), 'response preamble is empty')
        if rcvbuf is None:
            self.assertEqual(sock._recv_into_calls, 1)
        else:
            self.assertEqual(sock._recv_into_calls, 1)

        data = b'HTTP/1.1 200 OK\r\n\r\nHello naughty nurse!'
        (sock, reader) = self.new(data, rcvbuf=rcvbuf)
        response = reader.read_response('GET')
        self.assertIsInstance(response, self.ResponseType)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(response.headers, {})
        self.assertIs(response.body, None)
        self.assertEqual(response, (200, 'OK', {}, None))

        good = b'HTTP/1.1 200 OK'
        suffix = b'\r\n\r\nHello naughty nurse!'
        for i in range(len(good)):
            bad = bytearray(good)
            del bad[i]
            bad = bytes(bad)
            data = bad + suffix
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            with self.assertRaises(ValueError) as cm:
                reader.read_response('GET')
            self.assertEqual(str(cm.exception),
                'response line too short: {!r}'.format(bad)
            )
        indexes = list(range(9))
        indexes.append(12)
        for i in indexes:
            g = good[i]
            for b in range(256):
                if b == g:
                    continue
                bad = bytearray(good)
                bad[i] = b
                bad = bytes(bad)
                data = bad + suffix
                (sock, reader) = self.new(data, rcvbuf=rcvbuf)
                with self.assertRaises(ValueError) as cm:
                    reader.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad response line: {!r}'.format(bad)
                )

        template = 'HTTP/1.1 {:03d} OK\r\n\r\nHello naughty nurse!'
        for status in range(1000):
            data = template.format(status).encode()
            (sock, reader) = self.new(data, rcvbuf=rcvbuf)
            if 100 <= status <= 599:
                response = reader.read_response('GET')
                self.assertIsInstance(response, self.ResponseType)
                self.assertEqual(response.status, status)
                self.assertEqual(response.reason, 'OK')
                self.assertEqual(response.headers, {})
                self.assertIs(response.body, None)
                self.assertEqual(response, (status, 'OK', {}, None))
            else:
                with self.assertRaises(ValueError) as cm:
                    reader.read_response('GET')
                self.assertEqual(str(cm.exception),
                    'bad status: {!r}'.format('{:03d}'.format(status).encode())
                )

    def test_read_response(self):
        for rcvbuf in (None, 1, 2, 3):
            self.check_read_response(rcvbuf)

    def test_read(self):
        default = self.DEFAULT_PREAMBLE
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.read(-1)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 16777216; got -1'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.read(16777217)
        self.assertEqual(str(cm.exception),
            'need 0 <= size <= 16777216; got 16777217'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        self.assertEqual(reader.read(0), b'')
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        A = b'A' * 1024
        B = b'B' * default
        C = b'C' * 512
        D = b'D' * (default + 1)
        (sock, reader) = self.new(A + B + C + D)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        (sock, reader) = self.new(A + B + C + D, 3)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        (sock, reader) = self.new(A + B + C + D, 1)
        self.assertEqual(reader.read(1024), A)
        self.assertEqual(reader.read(default), B)
        self.assertEqual(reader.read(512), C)
        self.assertEqual(reader.read(default + 1), D)

        badsocket = BadSocket(17.0)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(TypeError) as cm:
            reader.read(12345)
        self.assertEqual(str(cm.exception),
            "received: need a <class 'int'>; got a <class 'float'>: 17.0"
        )

        smax = sys.maxsize * 2 + 1
        twosmax = smax * 2
        for badsize in (-twosmax, -smax, -1, 12346, smax, twosmax):
            badsocket = BadSocket(badsize)
            reader = self.Reader(badsocket, base.bodies)
            with self.assertRaises(ValueError) as cm:
                reader.read(12345)
            self.assertEqual(str(cm.exception),
                'need 0 <= received <= 12345; got {!r}'.format(badsize)
            )

        marker = random_id()
        exc = ValueError(marker)
        badsocket = BadSocket(exc)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(ValueError) as cm:
            reader.read(12345)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)

    def test_readinto(self):
        data = b'GET / HTTP/1.1\r\n\r\nHello naughty nurse!'

        (sock, reader) = self.new(data)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(bytearray(0))
        self.assertEqual(str(cm.exception),
            'need 1 <= len(buf) <= 16777216; got 0'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)

        (sock, reader) = self.new(data)
        buf = bytearray(16777217)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(buf)
        self.assertEqual(str(cm.exception),
            'need 1 <= len(buf) <= 16777216; got 16777217'
        )
        self.assertEqual(sock._rfile.tell(), 0)
        self.assertEqual(reader.rawtell(), 0)
        self.assertEqual(reader.tell(), 0)
        self.assertEqual(buf, b'\x00' * 16777217)

        (sock, reader) = self.new(data)
        buf = bytearray(1)
        self.assertEqual(reader.readinto(buf), 1)
        self.assertEqual(buf, b'G')

        (sock, reader) = self.new(data)
        buf = bytearray(16777216)
        self.assertEqual(reader.readinto(buf), len(data))
        self.assertEqual(buf, data + (b'\x00' * (len(buf) - len(data))))

        dst = memoryview(bytearray(12345))
        badsocket = BadSocket(17.0)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(TypeError) as cm:
            reader.readinto(dst)
        self.assertEqual(str(cm.exception),
            TYPE_ERROR.format('received', int, float, 17.0)
        )

        smax = sys.maxsize * 2 + 1
        twosmax = smax * 2
        for badsize in (-twosmax, -smax, -1, 12346, smax, twosmax):
            badsocket = BadSocket(badsize)
            reader = self.Reader(badsocket, base.bodies)
            with self.assertRaises(ValueError) as cm:
                reader.readinto(dst)
            self.assertEqual(str(cm.exception),
                'need 0 <= received <= 12345; got {!r}'.format(badsize)
            )

        marker = random_id()
        exc = ValueError(marker)
        badsocket = BadSocket(exc)
        reader = self.Reader(badsocket, base.bodies)
        with self.assertRaises(ValueError) as cm:
            reader.readinto(dst)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)


class TestReader_C(TestReader_Py):
    backend = _base


################################################################################
# Writer:



class WSocket:
    __slots__ = ('_ret', '_fp', '_calls')

    def __init__(self, **ret):
        self._ret = ret
        self._fp = io.BytesIO()
        self._calls = []

    def _return_or_raise(self, key, default):
        ret = self._ret.get(key, default)
        if isinstance(ret, Exception):
            raise ret
        return ret

    def shutdown(self, how):
        self._calls.append(('shutdown', how))
        return None

    def send(self, buf):
        assert isinstance(buf, memoryview)
        self._calls.append(('send', buf.tobytes()))
        size = self._fp.write(buf)
        return  self._return_or_raise('send', size)


class TestWriter_Py(BackendTestCase):
    @property
    def Writer(self):
        return self.getattr('Writer')

    @property
    def bodies(self):
        return self.getattr('bodies')

    def test_init(self):
        sock = WSocket()
        self.assertEqual(sys.getrefcount(sock), 2)
        bodies = base.bodies
        bcount = sys.getrefcount(bodies)
        counts = tuple(sys.getrefcount(b) for b in bodies)

        writer = self.Writer(sock, bodies)
        self.assertEqual(sys.getrefcount(sock), 3)
        self.assertEqual(sys.getrefcount(bodies), bcount)
        self.assertEqual(tuple(sys.getrefcount(b) for b in bodies),
            tuple(c + 1 for c in counts)
        )

        del writer
        self.assertEqual(sys.getrefcount(sock), 2)
        self.assertEqual(sys.getrefcount(bodies), bcount)
        self.assertEqual(tuple(sys.getrefcount(b) for b in bodies), counts)

    def test_tell(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)
        tell = writer.tell()
        self.assertIsInstance(tell, int)
        self.assertEqual(tell, 0)
        self.assertEqual(sock._calls, [])

    def test_write(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)

        data1 = os.urandom(17)
        self.assertEqual(writer.write(data1), 17)
        self.assertEqual(writer.tell(), 17)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

        data2 = os.urandom(18)
        self.assertEqual(writer.write(data2), 18)
        self.assertEqual(writer.tell(), 35)
        self.assertEqual(sock._fp.getvalue(), data1 + data2)
        self.assertEqual(sock._calls, [('send', data1), ('send', data2)])

        marker = random_id()
        exc = ValueError(marker)
        sock = WSocket(send=exc)
        writer = self.Writer(sock, base.bodies)
        with self.assertRaises(ValueError) as cm:
            writer.write(data1)
        self.assertIs(cm.exception, exc)
        self.assertEqual(str(cm.exception), marker)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

        # sock.send() doesn't return an int:
        for bad in (17.0, int_subclass(17)):
            self.assertEqual(bad, 17)
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(TypeError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                TYPE_ERROR.format('sent', int, type(bad), bad)
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        # sock.send() returns a bad int value:
        smin = -sys.maxsize - 1
        smax = sys.maxsize * 2 + 1
        for bad in (smin - 1, smin, -17, -1, 18, 19, smax, smax + 1):
            sock = WSocket(send=bad)
            writer = self.Writer(sock, base.bodies)
            with self.assertRaises(ValueError) as cm:
                writer.write(data1)
            self.assertEqual(str(cm.exception),
                'need 0 <= sent <= 17; got {!r}'.format(bad)
            )
            self.assertEqual(writer.tell(), 0)
            self.assertEqual(sock._fp.getvalue(), data1)
            self.assertEqual(sock._calls, [('send', data1)])

        sock = WSocket(send=0)
        writer = self.Writer(sock, base.bodies)
        with self.assertRaises(OSError) as cm:
            writer.write(data1)
        self.assertEqual(str(cm.exception), 'expected 17; send() returned 0')
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._fp.getvalue(), data1)
        self.assertEqual(sock._calls, [('send', data1)])

    def test_flush(self):
        sock = WSocket()
        writer = self.Writer(sock, base.bodies)
        self.assertIsNone(writer.flush())
        self.assertEqual(sock._calls, [])

    def test_write_output(self):
        bodies = base.bodies

        # Empty preamble and empty body:
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', None), 0)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sock._fp.getvalue(), b'')

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', b''), 0)
        self.assertEqual(writer.tell(), 0)
        self.assertEqual(sock._calls, [])
        self.assertEqual(sock._fp.getvalue(), b'')

        # Preamble plus empty body:
        preamble = os.urandom(34)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, None), 34)
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, b''), 34)
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        # body plus empty preamble:
        body = os.urandom(969)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(b'', body), 969)
        self.assertEqual(writer.tell(), 969)
        self.assertEqual(sock._calls, [('send', body)])
        self.assertEqual(sock._fp.getvalue(), body)

        # Body preamble and body are non-empty:
        body = os.urandom(969)
        sock = WSocket()
        writer = self.Writer(sock, bodies)
        self.assertEqual(writer.write_output(preamble, body), 1003)
        self.assertEqual(writer.tell(), 1003)
        self.assertEqual(sock._calls, [('send', preamble + body)])
        self.assertEqual(sock._fp.getvalue(), preamble + body)

        # no body.write_to attribute:
        class Body1:
            pass

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        body = Body1()
        with self.assertRaises(AttributeError) as cm:
            writer.write_output(preamble, body)
        self.assertEqual(str(cm.exception),
            "'Body1' object has no attribute 'write_to'"
        )
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        # body.write_to isn't callable:
        class Body2:
            write_to = 'nope'

        sock = WSocket()
        writer = self.Writer(sock, bodies)
        body = Body2()
        with self.assertRaises(TypeError) as cm:
            writer.write_output(preamble, body)
        self.assertEqual(str(cm.exception),
            "'str' object is not callable"
        )
        self.assertEqual(writer.tell(), 34)
        self.assertEqual(sock._calls, [('send', preamble)])
        self.assertEqual(sock._fp.getvalue(), preamble)

        class Body:
            def __init__(self, *chunks, **ret):
                self._chunks = chunks
                self._ret = ret

            def _return_or_raise(self, key, default):
                value = self._ret.get(key, default)
                if isinstance(value, Exception):
                    raise value
                return value

            def write_to(self, wfile):
                chunks = self._chunks
                self._chunks = None
                total = 0
                write = wfile.write
                total = sum(write(data) for data in chunks)
                return self._return_or_raise('write_to', total)

        data1 = os.urandom(17)
        data2 = os.urandom(18)
        chunks_permutations = (
            tuple(),
            (data1,),
            (data1, data2),
        )

        # body.write_to() raises an exception:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            marker = random_id()
            bad = ValueError(marker)
            body = Body(*chunks, write_to=bad)
            with self.assertRaises(ValueError) as cm:
                writer.write_output(preamble, body)
            self.assertIs(cm.exception, bad)
            self.assertEqual(str(cm.exception), marker)
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                [('send', preamble)] + [('send', d) for d in chunks]
            )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() doesn't return an int:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            body = Body(*chunks, write_to=17.0)
            with self.assertRaises(TypeError) as cm:
                writer.write_output(preamble, body)
            self.assertEqual(str(cm.exception),
                "total_wrote: need a <class 'int'>; got a <class 'float'>: 17.0"
            )
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                [('send', preamble)] + [('send', d) for d in chunks]
            )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() returns total < 0:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for bad in (-2**64, -2**64 + 1, -2, -1):
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                with self.assertRaises(ValueError) as cm:
                    writer.write_output(preamble, body)
                self.assertEqual(str(cm.exception),
                    'need 0 <= total_wrote <= 9999999999999999; got {!r}'.format(bad)
                )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() returns a bad length:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for bad in BAD_LENGTHS:
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                with self.assertRaises(ValueError) as cm:
                    writer.write_output(preamble, body)
                self.assertEqual(str(cm.exception),
                    'need 0 <= total_wrote <= 9999999999999999; got {!r}'.format(bad)
                )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # body.write_to() doesn't return the amount written with writer.write():
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks)
            for offset in (-2, -1, 1, 2):
                bad = total + offset
                sock = WSocket()
                writer = self.Writer(sock, bodies)
                body = Body(*chunks, write_to=bad)
                if bad < 0:
                    with self.assertRaises(ValueError) as cm:
                        writer.write_output(preamble, body)
                    self.assertEqual(str(cm.exception),
                        'need 0 <= total_wrote <= 9999999999999999; got {!r}'.format(bad)
                    )
                else:
                    with self.assertRaises(ValueError) as cm:
                        writer.write_output(preamble, body)
                    self.assertEqual(str(cm.exception),
                        '{!r} bytes were written, but write_to() returned {!r}'.format(
                            total, bad
                        )
                    )
                self.assertEqual(writer.tell(), total + len(preamble))
                self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
                self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))

        # All good:
        for chunks in chunks_permutations:
            total = sum(len(d) for d in chunks) + len(preamble)
            sock = WSocket()
            writer = self.Writer(sock, bodies)
            body = Body(*chunks)
            self.assertEqual(writer.write_output(preamble, body), total)
            self.assertEqual(writer.tell(), total)
            self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks]
                )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks))
            p = os.urandom(19)
            b = os.urandom(23)
            c = p + b
            self.assertEqual(writer.write_output(p, b), 42)
            self.assertEqual(writer.tell(), total + 42)
            self.assertEqual(sock._calls,
                    [('send', preamble)] + [('send', d) for d in chunks] + [('send', c)]
                )
            self.assertEqual(sock._fp.getvalue(), preamble + b''.join(chunks) + c)

    def test_set_default_headers(self):
        bodies = base.bodies
        writer = self.Writer(WSocket(), bodies)

        # body is None:
        headers = {}
        self.assertIsNone(writer.set_default_headers(headers, None))
        self.assertEqual(headers, {})

        headers = {'content-length': 17, 'transfer-encoding': 'chunked'}
        self.assertIsNone(writer.set_default_headers(headers, None))
        self.assertEqual(headers,
            {'content-length': 17, 'transfer-encoding': 'chunked'}
        )

        # bodies with a content-length:
        length_bodies = (
            os.urandom(17),
            bodies.Body(io.BytesIO(), 17),
            bodies.BodyIter([], 17),
        )
        for body in length_bodies:
            headers = {}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'content-length': 17})

            headers = {'content-length': 17}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'content-length': 17})

            headers = {'content-length': 16}
            with self.assertRaises(ValueError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                "'content-length' mismatch: 17 != 16"
            )
            self.assertEqual(headers, {'content-length': 16})

        # chunk-encoded bodies:
        chunked_bodies = (
            bodies.ChunkedBody(io.BytesIO()),
            bodies.ChunkedBodyIter([]),
        )
        for body in chunked_bodies:
            headers = {}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'transfer-encoding': 'chunked'})
    
            headers = {'transfer-encoding': 'chunked'}
            self.assertIsNone(writer.set_default_headers(headers, body))
            self.assertEqual(headers, {'transfer-encoding': 'chunked'})

            headers = {'transfer-encoding': 'clumped'}
            with self.assertRaises(ValueError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                "'transfer-encoding' mismatch: 'chunked' != 'clumped'"
            )

        # bad body types:
        bad_bodies = (
            random_id()[:17],
            io.BytesIO(os.urandom(17)),
        )
        for body in bad_bodies:
            headers = {}
            with self.assertRaises(TypeError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )
            self.assertEqual(headers, {})

            headers = {'content-length': 17, 'transfer-encoding': 'chunked'}
            with self.assertRaises(TypeError) as cm:
                writer.set_default_headers(headers, body)
            self.assertEqual(str(cm.exception),
                'bad body type: {!r}: {!r}'.format(type(body), body)
            )
            self.assertEqual(headers,
                {'content-length': 17, 'transfer-encoding': 'chunked'}
            )

    def test_write_request(self):
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        for method in BAD_METHODS:
            with self.assertRaises(ValueError) as cm:
                writer.write_request(method, '/', {}, None)
            self.assertEqual(str(cm.exception),
                'bad HTTP method: {!r}'.format(method)
            )

        # Empty headers, no body:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            18
        )
        self.assertEqual(headers, {})
        self.assertEqual(writer.tell(), 18)
        self.assertEqual(sock._fp.getvalue(), b'GET / HTTP/1.1\r\n\r\n')

        # One header:
        headers = {'foo': 17}  # Make sure to test with int header value
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            27
        )
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(writer.tell(), 27)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        headers = {'foo': 17, 'bar': 'baz'}
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, None),
            37
        )
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(writer.tell(), 37)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        self.assertEqual(
            writer.write_request('GET', '/', headers, b'hello'),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 42)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is bodies.Body:
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = self.bodies.Body(rfile, 5)
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            42
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(writer.tell(), 42)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
        )

#        # body is bodies.BodyIter:
#        headers = {}
#        body = self.bodies.BodyIter((b'hell', b'o'), 5)
#        sock = WSocket()
#        writer = self.Writer(sock, self.bodies)
#        self.assertEqual(
#            writer.write_request('GET', '/', headers, body),
#            42
#        )
#        self.assertEqual(headers, {'content-length': 5})
#        self.assertEqual(writer.tell(), 42)
#        self.assertEqual(sock._fp.getvalue(),
#            b'GET / HTTP/1.1\r\ncontent-length: 5\r\n\r\nhello'
#        )

        # body is base.ChunkedBody:
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = self.bodies.ChunkedBody(rfile)
        headers = {}
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            61
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(writer.tell(), 61)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.ChunkedBodyIter:
        headers = {}
        body = self.bodies.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        self.assertEqual(
            writer.write_request('GET', '/', headers, body),
            61
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(writer.tell(), 61)
        self.assertEqual(sock._fp.getvalue(),
            b'GET / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

    def test_write_response(self):
        # Empty headers, no body:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        self.assertEqual(
            writer.write_response(200, 'OK', headers, None),
            19
        )
        self.assertEqual(headers, {})
        self.assertEqual(writer.tell(), 19)
        self.assertEqual(sock._fp.tell(), 19)
        self.assertEqual(sock._fp.getvalue(), b'HTTP/1.1 200 OK\r\n\r\n')

        # One header:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {'foo': 17}  # Make sure to test with int header value
        self.assertEqual(
            writer.write_response(200, 'OK', headers, None),
            28
        )
        self.assertEqual(headers, {'foo': 17})
        self.assertEqual(writer.tell(), 28)
        self.assertEqual(sock._fp.tell(), 28)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\nfoo: 17\r\n\r\n'
        )

        # Two headers:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {'foo': 17, 'bar': 'baz'}
        self.assertEqual(writer.write_response(200, 'OK', headers, None), 38)
        self.assertEqual(headers, {'foo': 17, 'bar': 'baz'})
        self.assertEqual(writer.tell(), 38)
        self.assertEqual(sock._fp.tell(), 38)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\nbar: baz\r\nfoo: 17\r\n\r\n'
        )

        # body is bytes:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        self.assertEqual(
            writer.write_response(200, 'OK', headers, b'hello'),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.BodyIter:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        body = self.bodies.BodyIter((b'hell', b'o'), 5)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBodyIter:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        body = self.bodies.ChunkedBodyIter(
            ((None, b'hello'), (None, b''))
        )
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            62
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(writer.tell(), 62)
        self.assertEqual(sock._fp.tell(), 62)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )

        # body is base.Body:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        rfile = io.BytesIO(b'hello')
        body = self.bodies.Body(rfile, 5)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            43
        )
        self.assertEqual(headers, {'content-length': 5})
        self.assertEqual(rfile.tell(), 5)
        self.assertEqual(writer.tell(), 43)
        self.assertEqual(sock._fp.tell(), 43)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello'
        )

        # body is base.ChunkedBody:
        sock = WSocket()
        writer = self.Writer(sock, self.bodies)
        headers = {}
        rfile = io.BytesIO(b'5\r\nhello\r\n0\r\n\r\n')
        body = self.bodies.ChunkedBody(rfile)
        self.assertEqual(
            writer.write_response(200, 'OK', headers, body),
            62
        )
        self.assertEqual(headers, {'transfer-encoding': 'chunked'})
        self.assertEqual(rfile.tell(), 15)
        self.assertEqual(writer.tell(), 62)
        self.assertEqual(sock._fp.tell(), 62)
        self.assertEqual(sock._fp.getvalue(),
            b'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
        )
        


class TestWriter_C(TestWriter_Py):
    backend = _base

