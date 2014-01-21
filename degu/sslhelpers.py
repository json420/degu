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
Helpers for non-interactive creation of SSL certs.
"""

import os
from os import path
import stat
from subprocess import check_call, check_output
from hashlib import sha512

from dbase32 import random_id, db32enc


DAYS = 365 * 10  # Valid for 10 years


def hash_pubkey(pubkey_data):
    """
    Hash an RSA public key to compute its intrinsic ID.

    For example:

    >>> hash_pubkey(b'The PEM encoded public key')
    'XKDV44UR3BA66CGH8H34S6LVPG77L97PXE4KIAX3J7MNGHF9'

    """
    digest = sha512(pubkey_data).digest()
    return db32enc(digest[:30])


def make_subject(cn):
    """
    Make an openssl certificate subject from the common name *cn*.

    For example:

    >>> make_subject('foo')
    '/CN=foo'

    """
    return '/CN={}'.format(cn)


def create_key(dst_file, bits=2048):
    """
    Create an RSA keypair and save it to *dst_file*.
    """
    assert isinstance(bits, int)
    assert bits % 1024 == 0
    assert bits >= 1024
    check_call(['openssl', 'genrsa',
        '-out', dst_file,
        str(bits)
    ])


def create_ca(key_file, subject, dst_file):
    """
    Create a self-signed X509 certificate authority.

    *subject* should be an str in the form ``'/CN=foo'``.
    """
    check_call(['openssl', 'req',
        '-new',
        '-x509',
        '-sha384',
        '-days', str(DAYS),
        '-key', key_file,
        '-subj', subject,
        '-out', dst_file,
    ])


def create_csr(key_file, subject, dst_file):
    """
    Create a certificate signing request.

    *subject* should be an str in the form ``'/CN=foo'``.
    """
    check_call(['openssl', 'req',
        '-new',
        '-sha384',
        '-key', key_file,
        '-subj', subject,
        '-out', dst_file,
    ])


def issue_cert(csr_file, ca_file, key_file, srl_file, dst_file):
    """
    Create a signed certificate from a certificate signing request.
    """
    check_call(['openssl', 'x509',
        '-req',
        '-sha384',
        '-days', str(DAYS),
        '-CAcreateserial',
        '-in', csr_file,
        '-CA', ca_file,
        '-CAkey', key_file,
        '-CAserial', srl_file,
        '-out', dst_file
    ])


def get_rsa_pubkey(key_file):
    return check_output(['openssl', 'rsa',
        '-pubout',
        '-in', key_file,
    ])


def get_csr_pubkey(csr_file):
    return check_output(['openssl', 'req',
        '-pubkey',
        '-noout',
        '-in', csr_file,
    ])  


def get_pubkey(cert_file):
    return check_output(['openssl', 'x509',
        '-pubkey',
        '-noout',
        '-in', cert_file,
    ])


def ensuredir(d):
    try:
        os.mkdir(d)
    except OSError:
        mode = os.lstat(d).st_mode
        if not stat.S_ISDIR(mode):
            raise ValueError('not a directory: {!r}'.format(d))


class PKI:
    def __init__(self, ssldir):
        self.ssldir = ssldir
        self.tmpdir = path.join(ssldir, 'tmp')
        ensuredir(self.tmpdir)
        self.user = None
        self.machine = None

    def random_tmp(self):
        return path.join(self.tmpdir, random_id())

    def path(self, _id, ext):
        return path.join(self.ssldir, '.'.join([_id, ext]))

    def create_key(self, bits=2048):
        tmp_file = self.random_tmp()
        create_key(tmp_file, bits)
        _id = hash_pubkey(get_rsa_pubkey(tmp_file))
        key_file = self.path(_id, 'key')
        os.rename(tmp_file, key_file)
        return _id

    def create_ca(self, _id):
        key_file = self.path(_id, 'key')
        subject = make_subject(_id)
        tmp_file = self.random_tmp()
        ca_file = self.path(_id, 'ca')
        create_ca(key_file, subject, tmp_file)
        os.rename(tmp_file, ca_file)
        return ca_file

    def create_csr(self, _id):
        key_file = self.path(_id, 'key')
        subject = make_subject(_id)
        tmp_file = self.random_tmp()
        csr_file = self.path(_id, 'csr')
        create_csr(key_file, subject, tmp_file)
        os.rename(tmp_file, csr_file)
        return csr_file

    def issue_cert(self, _id, ca_id):
        csr_file = self.path(_id, 'csr')
        tmp_file = self.random_tmp()
        cert_file = self.path(_id, 'cert')
        ca_file = self.path(ca_id, 'ca')
        key_file = self.path(ca_id, 'key')
        srl_file = self.path(ca_id, 'srl')
        issue_cert(csr_file, ca_file, key_file, srl_file, tmp_file)
        os.rename(tmp_file, cert_file)
        return cert_file

