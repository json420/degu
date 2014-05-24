#!/usr/bin/python3

import timeit

setup = """
from degu.client import parse_status, iter_request_lines
from degu.server import parse_request, iter_response_lines
from degu.base import parse_headers

line_bytes = (b'L' *  50) + b'\\r\\n'
assert line_bytes.endswith(b'\\r\\n')
assert line_bytes[-2:] == b'\\r\\n'

lines = (
    'POST /foo/bar?stuff=junk HTTP/1.1',
    'Content-Type: application/json',
    'Accept: application/json',
    'Content-Length: 1234567',
    'User-Agent: Microfiber/14.04',
    'X-Token: VVI5KPPRN5VOG9DITDLEOEIB',
)

headers = {
    'content-cype': 'application/json',
    'accept': 'application/json',
    'content-length': 1234567,
    'user-agent': 'Microfiber/14.04',
    'x-token': 'VVI5KPPRN5VOG9DITDLEOEIB',
}
"""


def run_iter(statement, n):
    for i in range(5):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=250):
    n = K * 1000
    # Choose fastest of 5 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>12,}: {}'.format(rate, statement))


print('Validate and decode line_bytes:')
run("line_bytes.endswith(b'\\r\\n')")
run("line_bytes[-2:] == b'\\r\\n'")
run("line_bytes[:-2].decode('latin_1')")
run("line_bytes[:-2].decode('utf-8')")
run("line_bytes[:-2].decode()")
run("line_bytes.decode()")

print('\nBuild Request/Response Preamble:')
run("''.join(iter_request_lines('GET', '/foo/bar?stuff=junk', headers))")
run("''.join(iter_response_lines(200, 'OK', headers))")

print('\nSplit performance:')
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split(' ', 2)")
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split(' ')")
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split()")
run("(method, uri, protocol) = 'GET /foo/bar?stuff=junk HTTP/1.1'.split()")

print('\nMisc performance:')
run("'Content-Length'.casefold()")
run("int('1234567')")
run("'HTTP/1.1 {:d} {}\\r\\n'.format(200, 'OK')")
run("'HTTP/1.1 {} {}\\r\\n'.format(200, 'OK')")

print('\nHigh-level parsers:')
run("parse_status('HTTP/1.1 404 Not Found')")
run('parse_request(lines[0])')
run('parse_headers(lines[1:])')


print('-' * 80)

