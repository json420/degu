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


class MockSocket:
    __slots__ = (
        '_rfile',
        '_wfile',
        '_rcvbuf',
        '_sndbuf',
        '_calls',
        '_calls_close',
        '_calls_recv_into',
        '_calls_send',
    )

    def __init__(self, data=b'', rcvbuf=None, sndbuf=None):
        assert rcvbuf is None or (type(rcvbuf) is int and rcvbuf > 0)
        assert sndbuf is None or (type(sndbuf) is int and sndbuf > 0)
        self._rfile = io.BytesIO(data)
        self._wfile = io.BytesIO()
        self._rcvbuf = rcvbuf
        self._sndbuf = sndbuf
        self._calls = []
        self._calls_close = 0
        self._calls_recv_into = 0
        self._calls_send = 0

    def close(self):
        self._calls.append('close')
        self._calls_close += 1

    def recv_into(self, dst):
        assert type(dst) is memoryview
        self._calls.append(('recv_into', len(dst)))
        self._calls_recv_into += 1
        if self._rcvbuf is not None:
            dst = dst[0:self._rcvbuf]
        return self._rfile.readinto(dst)

    def send(self, src):
        assert type(src) in (bytes, memoryview)
        self._calls.append(('send', len(src)))
        self._calls_send += 1
        if self._sndbuf is not None:
            src = src[0:self._sndbuf]
        return self._wfile.write(src)


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


