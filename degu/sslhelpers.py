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

from subprocess import check_call


DAYS = 365 * 10  # Valid for 10 years


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

