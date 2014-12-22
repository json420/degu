#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from io import BytesIO

from degu._base import (
    parse_preamble,
    parse_response_line,
    parse_request_line,
    parse_method,
)

from degu import _base, _basepy
from degu.base import bodies, _read_preamble, write_chunk
from degu.client import _write_request
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
    for i in range(10):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=150):
    n = K * 1000
    # Choose fastest of 10 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>12,}: {}'.format(rate, statement))
    return rate


print('\nSimple parsers:')
run("parse_response_line(b'HTTP/1.1 200 OK')")
run("parse_response_line(b'HTTP/1.1 404 Not Found')")
run("parse_request_line(b'GET / HTTP/1.1')")
run("parse_request_line(b'DELETE /foo/bar?stuff=junk HTTP/1.1')")
run("parse_method(b'GET')")
run("parse_method(b'PUT')")
run("parse_method(b'POST')")
run("parse_method(b'HEAD')")
run("parse_method(b'DELETE')")

print('\nFormatting request preamble:')
run("_base.format_request_preamble('GET', '/foo', {})")
run("_basepy.format_request_preamble('GET', '/foo', {})")
run("_base.format_request_preamble('PUT', '/foo', {'content-length': 17})")
run("_basepy.format_request_preamble('PUT', '/foo', {'content-length': 17})")
run("_base.format_request_preamble('PUT', '/foo', headers)")
run("_basepy.format_request_preamble('PUT', '/foo', headers)")

print('\nFormatting response preamble:')
run("_base.format_response_preamble(200, 'OK', {})")
run("_basepy.format_response_preamble(200, 'OK', {})")
run("_base.format_response_preamble(200, 'OK', {'content-length': 17})")
run("_basepy.format_response_preamble(200, 'OK', {'content-length': 17})")
run("_base.format_response_preamble(200, 'OK', headers)")
run("_basepy.format_response_preamble(200, 'OK', headers)")

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

print('\nHigh-level formatters:')
run("_write_response(wfile, 200, 'OK', headers, b'hello, world')")
run("_write_request(wfile, 'PUT', '/foo/bar?stuff=junk', headers, b'hello, world')")
run("write_chunk(wfile, (None, data))")
run("write_chunk(wfile, (('foo', 'bar'), data))")

print('-' * 80)

