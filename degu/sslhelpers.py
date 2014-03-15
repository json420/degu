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

This is an extremely trimmed-down version of the Dmedia Identity framework:

    http://bazaar.launchpad.net/~dmedia/dmedia/trunk/view/head:/dmedia/identity.py

Unlike the rest of Degu, this module isn't meant for production use and is
really only aimed at unit testing.

With time, we may move the Dmedia Identity framework into Degu, or at least a
slightly more generalized version of it.  But for now, we're focused on refining
the Degu server and client.

Note that at least for now, we want Degu to only depend on the Python standard
library, so we're using RFC-3548 Base32 encoding for the intrinsic IDs (content
hash of the RSA public key), rather than using Dbase32:

    https://launchpad.net/dbase32

However, be warned that the Dbase32 encoding plays a key role in our long-term
database plans for Novacut and Dmedia, so it might not always be possible to use
RFC-3548 Base32 encoding in that context.
"""

import os
from os import path
import stat
from subprocess import check_call, check_output
from hashlib import sha512
from base64 import b32encode


DAYS = 365 * 10  # Valid for 10 years


def b32enc(data):
    """
    Similar to `dbase32.db32enc()`, but using RFC-3548 Base32 encoding.
    """
    assert 5 <= len(data) <= 60 and len(data) % 5 == 0
    return b32encode(data).decode()


def random_id(numbytes=15):
    """
    Similar to `dbase32.random_id()`, but using RFC-3548 Base32 encoding.
    """
    assert 5 <= numbytes <= 60 and numbytes % 5 == 0
    return b32enc(os.urandom(numbytes))


def hash_pubkey(pubkey_data):
    """
    Hash an RSA public key to compute its intrinsic ID.

    For example:

    >>> hash_pubkey(b'The PEM encoded public key')
    '6RK4BB3YAIHDDJNOFOABZDS4WNEESGEW6LBRPH6AQETUNOMG'

    """
    digest = sha512(pubkey_data).digest()
    return b32enc(digest[:30])


def make_subject(cn):
    """
    Make an openssl certificate subject from the common name *cn*.

    For example:

    >>> make_subject('foo')
    '/CN=foo'

    """
    return '/CN={}'.format(cn)


def create_key(dst_file, bits=4096):
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

    def __repr__(self):
        return '{}({!r})'.format(self.__class__.__name__, self.ssldir)

    def random_tmp(self):
        return path.join(self.tmpdir, random_id())

    def path(self, _id, ext):
        return path.join(self.ssldir, '.'.join([_id, ext]))

    def create_key(self, bits=4096):
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

    def get_server_config(self, server_id, client_ca_id=None):
        config = {
            'cert_file': self.path(server_id, 'cert'),
            'key_file': self.path(server_id, 'key'),
        }
        if client_ca_id:
            config['ca_file'] = self.path(client_ca_id, 'ca')
        return config

    def get_anonymous_server_config(self, server_id):
        """
        Server will accept connections from unauthenticated client.
        """
        return {
            'cert_file': self.path(server_id, 'cert'),
            'key_file': self.path(server_id, 'key'),
            'allow_unauthenticated_clients': True,
        }

    def get_client_config(self, server_ca_id, client_id=None):
        config = {
            'ca_file': self.path(server_ca_id, 'ca'),
            'check_hostname': False,
        }
        if client_id:
            config['cert_file'] = self.path(client_id, 'cert')
            config['key_file'] = self.path(client_id, 'key')
        return config

    def get_anonymous_client_config(self, server_ca_id):
        return {
            'ca_file': self.path(server_ca_id, 'ca'),
            'check_hostname': False,
        }
