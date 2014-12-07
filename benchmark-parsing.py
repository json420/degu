#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from io import BytesIO

from degu import _base, _basepy
from degu._base import parse_preamble
from degu.base import bodies, _read_preamble, write_chunk
from degu.client import _parse_status, _write_request
from degu.server import _read_request, _write_response

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
_write_request(fp, 'POST', '/foo/bar?stuff=junk', headers, None)
request_preamble = fp.getvalue()
assert request_preamble.endswith(b'\\r\\n\\r\\n'), request_preamble
preamble = request_preamble[:-4]
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

print('\nHigh-level formatters:')
run("_base.format_request_preamble('GET', '/foo', {})")
run("_basepy.format_request_preamble('GET', '/foo', {})")
run("_base.format_request_preamble('PUT', '/foo', {'content-length': 17})")
run("_basepy.format_request_preamble('PUT', '/foo', {'content-length': 17})")
run("_base.format_request_preamble('PUT', '/foo', headers)")
run("_basepy.format_request_preamble('PUT', '/foo', headers)")
raise SystemExit()

print('\nFormatting and encoding:')
run("'HTTP/1.1 {} {}\\r\\n'.format(404, 'Not Found')")
run("'{} {} HTTP/1.1\\r\\n'.format('GET', '/foo/bar?stuff=junk')")
run("'{}: {}\\r\\n'.format('content-length', 1234567)")
run("'GET /foo/bar?stuff=junk HTTP/1.1\\r\\n'.encode('latin_1')")

print('\nHigh-level parsers:')
run('parse_preamble(preamble)')
run("parse_preamble(b'hello\\r\\ncontent-length: 17')")
run("parse_preamble(b'hello\\r\\ntransfer-encoding: chunked')")
run('_read_preamble(BytesIO(request_preamble))')
run('_read_request(BytesIO(request_preamble), bodies)')
run("_parse_status('HTTP/1.1 404 Not Found')")

print('\nHigh-level formatters:')
run("_write_response(wfile, 200, 'OK', headers, b'hello, world')")
run("_write_request(wfile, 'PUT', '/foo/bar?stuff=junk', headers, b'hello, world')")
run("write_chunk(wfile, (None, data))")
run("write_chunk(wfile, (('foo', 'bar'), data))")

print('-' * 80)

