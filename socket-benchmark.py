#!/usr/bin/python3

"""
Benchmark low-level Python `socket` performance.

This benchmark gives us an upper bound on the performance we can achieve for
sequential request/response through a single TCP connection.
"""

import multiprocessing
import socket
import os
import tempfile
import shutil
import time


size = 512
request = os.urandom(size)
response = os.urandom(size)


def create_socket(address):
    if isinstance(address, tuple):
        if len(address) == 2:
            family = socket.AF_INET
        elif len(address) == 4:
            family = socket.AF_INET6
        else:
            raise ValueError()
    elif isinstance(address, (str, bytes)):
        family = socket.AF_UNIX
    else:
        raise TypeError()
    return socket.socket(family, socket.SOCK_STREAM)


def get_socket_bufsizes(sock):
    return (
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
    )


def print_socket_bufsizes(sock, endpoint):
    (rcvbuf, sndbuf) = get_socket_bufsizes(sock)
    print('    {}: rcvbuf={!r}, sndbuf={!r}'.format(endpoint, rcvbuf, sndbuf))


def run_server(q, address):
    sock = create_socket(address)
    print_socket_bufsizes(sock, 'server')
    sock.bind(address)
    sock.listen(5)
    q.put(sock.getsockname())
    (s, a) = sock.accept()
    while True:
        s.recv(size)
        s.send(response)


def start_server(address):
    q = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=run_server,
        args=(q, address),
        daemon=True,
    )
    process.start()
    address = q.get()
    return (process, address)


def run_client(address, count):
    sock = create_socket(address)
    print_socket_bufsizes(sock, 'client')
    sock.connect(address)
    for i in range(count):
        sock.send(request)
        sock.recv(size)


def run_benchmark(label, address):
    print('{}:'.format(label))
    (process, address) = start_server(address)
    count = 150 * 1000
    start = time.monotonic()
    run_client(address, count)
    elapsed = time.monotonic() - start
    print('{:,} messages per second\n'.format(int(count / elapsed)))
    process.terminate()
    process.join()


tmpdir = tempfile.mkdtemp(prefix='sock.')
pairs = (
    ('AF_UNIX', os.path.join(tmpdir, 'my.socket')),
    ('AF_INET', ('127.0.0.1', 0)),
    ('AF_INET6', ('::1', 0, 0, 0)),
)
for (label, address) in pairs:
    time.sleep(2)
    run_benchmark(label, address)
shutil.rmtree(tmpdir)

