#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from io import BytesIO

import _degu
from degu.client import parse_status, write_request
from degu.server import parse_request, read_request, write_response
from degu.base import write_chunk

line = (b'L' *  50) + b'\\r\\n'
assert line.endswith(b'\\r\\n')
assert line[-2:] == b'\\r\\n'


headers = {
    'content-type': 'application/json',
    'accept': 'application/json',
    'content-length': 12,
    'user-agent': 'Microfiber/14.04',
    'x-token': 'VVI5KPPRN5VOG9DITDLEOEIB',
    'extra': 'Super',
    'hello': 'World',
    'k': 'V',
}

fp = BytesIO()
write_request(fp, 'POST', '/foo/bar?stuff=junk', headers, b'hello')
request_preamble = fp.getvalue()
del fp

data = b'D' * 1776


class wfile:
    @staticmethod
    def write(data):
        return len(data)

    @staticmethod
    def flush():
        pass

"""


def run_iter(statement, n):
    for i in range(20):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=100):
    n = K * 1000
    # Choose fastest of 20 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>12,}: {}'.format(rate, statement))
    return rate


print('Decoding:')
run("line.decode('latin_1')")
run("line.decode('ascii')")
run("line.decode()")

print('\nSplit performance:')
run("(method, uri, protocol) = 'GET /foo/bar?stuff=junk HTTP/1.1'.split()")
run("(protocol, status, reason) = 'HTTP/1.1 404 Not Found'.split(' ', 2)")
run("(key, value) = 'Content-Length: 1234567'.split(': ')")

print('\nFormatting and encoding:')
run("'HTTP/1.1 {} {}\\r\\n'.format(404, 'Not Found')")
run("'{} {} HTTP/1.1\\r\\n'.format('GET', '/foo/bar?stuff=junk')")
run("'{}: {}\\r\\n'.format('content-length', 1234567)")
run("'GET /foo/bar?stuff=junk HTTP/1.1\\r\\n'.encode('latin_1')")

print('\nHigh-level parsers:')
run('_degu.read_preamble(BytesIO(request_preamble))')
run('read_request(BytesIO(request_preamble))')
run("parse_request('POST /foo/bar?stuff=junk HTTP/1.1')")
run("parse_status('HTTP/1.1 404 Not Found')")

print('\nHigh-level formatters:')
run("write_response(wfile, 200, 'OK', headers, b'hello, world')")
run("write_request(wfile, 'PUT', '/foo/bar?stuff=junk', headers, b'hello, world')")
run("write_chunk(wfile, data)")
run("write_chunk(wfile, data, ('foo', 'bar'))")

print('-' * 80)

