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
Unit test helpers.
"""

import io
import sys
import os
from os import path
import tempfile
import shutil
from random import SystemRandom
from unittest import TestCase
import string

from degu import tables
from degu.sslhelpers import random_id
from degu.base import _MAX_LINE_SIZE


random = SystemRandom()


def random_data():
    """
    Return random bytes between 1 and 34969 (inclusive) bytes long.

    In unit tests, this is used to simulate a random request or response body,
    or a random chunk in a chuck-encoded request or response body.
    """
    size = random.randint(1, 34969)
    return os.urandom(size)


def random_chunks():
    """
    Return between 0 and 10 random chunks (inclusive).

    There will always be 1 additional, final chunk, an empty ``b''``, as per the
    HTTP/1.1 specification.
    """
    count = random.randint(0, 10)
    chunks = [random_data() for i in range(count)]
    chunks.append(b'')
    return chunks


def random_identifier():
    return ''.join(random.choice(string.ascii_lowercase) for i in range(17))


def _iter_good(size, allowed):
    assert isinstance(size, int) and size >= 0
    assert isinstance(allowed, bytes)
    for okay in allowed:
        yield bytes(okay for i in range(size))


def _iter_bad(size, allowed, skip):
    assert isinstance(size, int) and size >= 0
    assert isinstance(allowed, bytes)
    assert isinstance(skip, bytes) and b'\n' in skip
    thebad = []
    for i in range(256):
        if i in allowed:
            continue  # Not actually bad!
        if i in skip:
            continue  # Other values we should skip
        thebad.append(i)
    for good in _iter_good(size, allowed):
        for bad in thebad:
            for index in range(size):
                notgood = bytearray(good)
                notgood[index] = bad  # Make good bad
                yield bytes(notgood)


def iter_bad_keys(size):
    yield from _iter_bad(size, tables.NAMES_DEF, b'\n')


def iter_good(good, allowed):
    for i in range(len(good)):
        for g in allowed:
            also_good = bytearray(good)
            also_good[i] = g
            yield bytes(also_good)


def iter_bad(good, allowed):
    assert isinstance(good, bytes)
    assert isinstance(allowed, bytes)
    not_allowed = tables.invert(allowed)
    for i in range(len(good)):
        for b in not_allowed:
            bad = bytearray(good)
            bad[i] = b
            yield bytes(bad)


class TempDir:
    def __init__(self, prefix='unittest.'):
        self.dir = tempfile.mkdtemp(prefix=prefix)

    def __del__(self):
        shutil.rmtree(self.dir)

    def join(self, *parts):
        return path.join(self.dir, *parts)

    def mkdir(self, *parts):
        dirname = self.join(*parts)
        os.mkdir(dirname)
        return dirname

    def makedirs(self, *parts):
        dirname = self.join(*parts)
        os.makedirs(dirname)
        return dirname

    def touch(self, *parts):
        filename = self.join(*parts)
        open(filename, 'xb').close()
        return filename

    def create(self, *parts):
        filename = self.join(*parts)
        return (filename, open(filename, 'xb'))

    def write(self, data, *parts):
        (filename, fp) = self.create(*parts)
        fp.write(data)
        fp.close()
        return filename

    def prepare(self, content):
        filename = self.write(content, random_id())
        return open(filename, 'rb')


class DummySocket:
    def __init__(self):
        self._calls = []
        self._rfile = random_id()
        self._wfile = random_id()

    def makefile(self, mode, **kw):
        self._calls.append(('makefile', mode, kw))
        if mode == 'rb':
            return self._rfile
        if mode == 'wb':
            return self._wfile

    def shutdown(self, how):
        self._calls.append(('shutdown', how))

    def close(self):
        self._calls.append('close')


class DummyFile:
    def __init__(self):
        self._calls = []

    def close(self):
        self._calls.append('close')


class FuzzTestCase(TestCase):
    """
    Base class for fuzz-testing read functions.
    """

    def fuzz(self, func, *args):
        """
        Perform random fuzz test on *func*.

        Expected result: given an rfile containing 8192 random bytes, func()
        should raise a ValueError every time, should read at least 1 byte, and
        should never read more than 4096 bytes.
        """
        for i in range(1000):
            data = os.urandom(_MAX_LINE_SIZE * 2)
            rfile = io.BytesIO(data)
            self.assertEqual(sys.getrefcount(rfile), 2)
            with self.assertRaises(ValueError):
                func(rfile, *args)
            self.assertGreaterEqual(rfile.tell(), 1)
            self.assertLessEqual(rfile.tell(), _MAX_LINE_SIZE)
            # Make sure refcount is still correct (especially important for
            # testing C extensions):
            self.assertEqual(sys.getrefcount(rfile), 2)


class MockBodies:
    def __init__(self, **kw):
        for (key, value) in kw.items():
            assert key in ('Body', 'BodyIter', 'ChunkedBody', 'ChunkedBodyIter')
            setattr(self, key, value)


def iter_bodies_with_missing_object():
    names = ('Body', 'BodyIter', 'ChunkedBody', 'ChunkedBodyIter')

    def dummy_body():
        pass

    for name in names:
        kw = dict((key, dummy_body) for key in names)
        del kw[name]
        yield (MockBodies(**kw), name)


def iter_bodies_with_non_callable_object():
    names = ('Body', 'BodyIter', 'ChunkedBody', 'ChunkedBodyIter')

    def dummy_body():
        pass

    for name in names:
        kw = dict((key, dummy_body) for key in names)
        attr = random_identifier()
        kw[name] = attr
        yield (MockBodies(**kw), name, attr)

