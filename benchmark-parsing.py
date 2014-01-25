#!/usr/bin/python3

import timeit

setup = """
from degu.client import parse_status
from degu.server import parse_request
from degu.base import parse_header, parse_headers

line_bytes = (b'L' *  50) + b'\\r\\n'
assert line_bytes.endswith(b'\\r\\n')
assert line_bytes[-2:] == b'\\r\\n'

lines = (
    'POST /foo/bar?stuff=junk HTTP/1.1',
    'Content-Type: application/json',
    'Accept: application/json',
    'Content-Length: 1234567',
    'User-Agent: Microfiber/14.04',
)
"""


def run(statement, K=250):
    t = timeit.Timer(statement, setup)
    n = K * 1000
    elapsed = t.timeit(n)
    rate = int(n / elapsed)
    print('{:>14,}: {}'.format(rate, statement))

print('Validate and decode line_bytes:')
run("line_bytes.endswith(b'\\r\\n')")
run("line_bytes[-2:] == b'\\r\\n'")
run("line_bytes[:-2].decode('latin_1')")
run("line_bytes[:-2].decode('utf-8')")
run("line_bytes[:-2].decode()")

print('\nSplit performance:')
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split(' ', 2)")
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split(' ')")
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split()")
run("'Content-Length: 1234567'.split(': ', 1)")
run("'Content-Length: 1234567'.split(': ')")
run("'/foo/bar/baz?stuff=junk&hello=nurse'.split('?', 1)")
run("'/foo/bar/baz?stuff=junk&hello=nurse'.split('?')")
run("'/foo/bar/baz?stuff=junk&hello=nurse'.find('?')")

print('\nMisc performance:')
run("'Content-Length'.casefold()")
run("int('1234567')")

print('\nHigh-level parsers:')
run("parse_status('HTTP/1.1 404 Not Found')")
run('parse_request(lines[0])')
run('parse_headers(lines[1:])')


print('-' * 80)

