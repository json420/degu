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
Unit test helpers.
"""

import io
import os
from os import path
import tempfile
import shutil
from random import SystemRandom
import string

from degu import tables
from degu.sslhelpers import random_id


MAX_IO_SIZE = 16777216  # 16 MiB
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


def random_chunk_ext():
    if random.randrange(3) == 0:
        return None
    return (random_identifier(), random_identifier())

def random_chunk(size=None):
    if size is None:
        size = random.randint(1, 34969)
    assert type(size) is int and 0 <= size <= MAX_IO_SIZE
    ext = random_chunk_ext()
    data = os.urandom(size)
    return (ext, data)

def random_chunks2(count=None):
    """
    Return between 0 and 10 random chunks (inclusive).

    There will always be 1 additional, final chunk, an empty ``b''``, as per the
    HTTP/1.1 specification.
    """
    if count is None:
        count = random.randrange(10) + 1
    assert type(count) is int and count > 0
    chunks = [
        random_chunk() for i in range(count - 1)
    ]
    chunks.append(random_chunk(0))
    assert len(chunks) == count
    return tuple(chunks)


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
    __slots__ = ('_calls',)

    def __init__(self):
        self._calls = []

    def shutdown(self, how):
        self._calls.append(('shutdown', how))

    def recv_into(self, buf):
        self._calls.append(('recv_into', buf))

    def send(self, buf):
        self._calls.append(('send', buf))


class DummyFile:
    def __init__(self):
        self._calls = []

    def close(self):
        self._calls.append('close')


class MockSocket:
    __slots__ = ('_rfile', '_wfile', '_rcvbuf', '_recv_into_calls', '_calls')

    def __init__(self, data, rcvbuf=None):
        assert rcvbuf is None or (isinstance(rcvbuf, int) and rcvbuf > 0)
        self._rfile = io.BytesIO(data)
        self._wfile = io.BytesIO()
        self._rcvbuf = rcvbuf
        self._recv_into_calls = 0
        self._calls = []

    def recv_into(self, buf):
        assert isinstance(buf, memoryview)
        self._calls.append(('recv_into', len(buf)))
        if self._rcvbuf is not None and len(buf) > self._rcvbuf:
            buf = buf[0:self._rcvbuf]
        self._recv_into_calls += 1
        return self._rfile.readinto(buf)

    def send(self, data):
        return self._wfile.write(data)


class MockSocket2:
    __slots__ = ('__rfile', '__rcvbuf')

    def __init__(self, rfile, rcvbuf=None):
        assert rcvbuf is None or (type(rcvbuf) is int and rcvbuf > 0)
        self.__rfile = rfile
        self.__rcvbuf = rcvbuf

    def recv_into(self, buf):
        assert isinstance(buf, memoryview)
        if self.__rcvbuf is not None:
            buf = buf[0:self.__rcvbuf]
        return self.__rfile.readinto(buf)


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


def build_uri(path, query):
    uri = '/' + '/'.join(path)
    if query is None:
        return uri
    return '?'.join([uri, query])


def iter_random_path():
    yield []
    for length in range(1, 5):
        p = [random_id() for i in range(length)]
        yield p
        yield p + [''] 


def iter_random_uri():
    queries = (
        None,
        random_id(),
        '{}={}'.format(random_id(), random_id()),
        '{}={}&{}={}'.format(random_id(), random_id(), random_id(), random_id())
    )
    for p in iter_random_path():
        for q in queries:
            yield (build_uri(p, q), p, q)


