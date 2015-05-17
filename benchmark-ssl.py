#!/usr/bin/python3

"""
Benchmark file transfer rate over SSL.

This benchmark simulates file-transfer as used by Dmedia, a scenario where there
is little HTTP overhead (because the files are large), and also little concern
for the cost of creating the SSL connection (both because the files are large,
and also because Dmedia will typically request many files through the same
connection).

Our goal is to be able to saturate a 10 gigabit local Ethernet connection with a
single connection, and a single CPU core.  On Haswell processors, we're already
very close to this as the GCM modes (authenticated encryption) in TLS 1.2 are
very fast.

Example results on an i7-4900MQ (2.8 GHz, 64-bit Ubuntu 14.04, Python 3.4)::

    cipher: ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256)
    runs: [2.8518437089987856, 2.8778152399991086, 2.858511821999855]
    fastest run: 2.8518437089987856
    transfer rate in fastest run: 941 MB/s

That's 7528 M bit/s, so we're about 75% the way there.  Of course, with multiple
parallel connections on multiple cores, we can fully saturate 10 gigabit today.

Even on 64-bit systems, there is a small performance improvement with AES-128,
but perhaps not enough to justify the switch (something to consider though)::

    cipher: ('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128)
    runs: [2.647685547000947, 2.6391498539996974, 2.6463401510009135]
    fastest run: 2.6391498539996974
    transfer rate in fastest run: 1.02 GB/s
"""

import time
import logging
import os
import math

from degu import IPv6_LOOPBACK
from degu.misc import TempPKI, TempSSLServer
from degu.client import SSLClient


logging.basicConfig(
    level=logging.DEBUG,
    format='\t'.join([
        '%(levelname)s',
        '%(threadName)s',
        '%(message)s',
    ]),
)


BYTES10 = (
    'bytes',
    'kB',
    'MB',
    'GB',
    'TB',
    'PB',
    'EB',
    'ZB',
    'YB',
)


def bytes10(size):
    if size is None:
        return None
    if size < 0:
        raise ValueError('size must be >= 0; got {!r}'.format(size))
    if size == 0:
        return '0 bytes'
    if size == 1:
        return '1 byte'
    i = min(int(math.floor(math.log(size, 1000))), len(BYTES10) - 1)
    s = (size / (1000 ** i) if i > 0 else size)
    return (
        '{:.3g} {}'.format(s, BYTES10[i])
    )


MiB = 1048576
chunk_size = MiB
unique_chunks = tuple(os.urandom(chunk_size) for i in range(8))
chunks = unique_chunks * 64  # 512 MiB 
content_length = sum(len(c) for c in chunks)


def file_app(session, request, bodies):
    headers = {'content-type': 'video/quicktime'}
    body = bodies.BodyIter(chunks, content_length)
    return (200, 'OK', headers, body)


pki = TempPKI()
server = TempSSLServer(pki.server_sslconfig, IPv6_LOOPBACK, file_app)
client = SSLClient(pki.client_sslconfig, server.address)


count = 5
deltas = []
for i in range(5):
    conn = client.connect()
    start = time.monotonic()
    for i in range(count):
        r = conn.request('GET', '/', {}, None)
        cipher = conn.sock.cipher()
        for block in r.body:
            pass
    deltas.append(time.monotonic() - start)
    conn.close()
server.terminate()
fastest = min(deltas)
rate = (content_length * count) / fastest
print('')
print('cipher: {}'.format(cipher))
print('runs: {}'.format(deltas))
print('fastest run: {}'.format(fastest))
print('transfer rate in fastest run: {}/s'.format(bytes10(int(rate))))

