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

import os
from os import path
import tempfile
import shutil

from dbase32 import random_id


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
        self._rb = random_id()
        self._wb = random_id()

    def makefile(self, mode, **kw):
        self._calls.append(('makefile', mode, kw))
        if mode == 'rb':
            return self._rb
        if mode == 'wb':
            return self._wb

    def shutdown(self, how):
        self._calls.append(('shutdown', how))

    def close(self):
        self._calls.append('close')
