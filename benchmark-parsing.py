#!/usr/bin/python3

import timeit

setup = """
from degu.client import parse_status, write_request
from degu.server import parse_request, write_response
from degu.base import parse_headers

line = (b'L' *  50) + b'\\r\\n'
assert line.endswith(b'\\r\\n')
assert line[-2:] == b'\\r\\n'

header_lines = (
    'Content-Type: application/json',
    'Accept: application/json',
    'Content-Length: 1234567',
    'User-Agent: Microfiber/14.04',
    'X-Token: VVI5KPPRN5VOG9DITDLEOEIB',
    'Extra: Super',
    'Hello: World',
)

headers = parse_headers(header_lines)


class wfile:
    @staticmethod
    def write(data):
        return len(data)

    @staticmethod
    def flush():
        pass

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


print('Validate and decode line:')
run("line.endswith(b'\\r\\n')")
run("line[-2:] == b'\\r\\n'")
run("line[:-2].decode('latin_1')")
run("line[:-2].decode()")
run("line.decode()")

print('\nSplit performance:')
run("(method, uri, protocol) = 'GET /foo/bar?stuff=junk HTTP/1.1'.split()")
run("(protocol, status, reason) = 'HTTP/1.1 404 Not Found'.split(' ', 2)")
run("(key, value) = 'Content-Length: 1234567'.split(': ')")

print('\nFormatting and encoding')
run("'HTTP/1.1 {} {}\\r\\n'.format(404, 'Not Found')")
run("'{} {} HTTP/1.1\\r\\n'.format('GET', '/foo/bar?stuff=junk')")
run("'{}: {}\\r\\n'.format('content-length', 1234567)")
run("'GET /foo/bar?stuff=junk HTTP/1.1\\r\\n'.encode('latin_1')")

print('\nHigh-level parsers:')
run("parse_request('POST /foo/bar?stuff=junk HTTP/1.1')")
run("parse_status('HTTP/1.1 404 Not Found')")
run('parse_headers(header_lines)')

print('\nHigh-level formatters:')
run("write_response(wfile, 404, 'Not Found', headers, None)")
run("write_request(wfile, 'GET', '/foo/bar?stuff=junk', headers, None)")

print('-' * 80)

