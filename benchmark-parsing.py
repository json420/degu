#!/usr/bin/python3

import timeit

setup = """
from degu.client import parse_status
from degu.server import parse_request
from degu.base import parse_header

line_bytes = (b'L' *  50) + b'\\r\\n'
assert line_bytes.endswith(b'\\r\\n')
assert line_bytes[-2:] == b'\\r\\n'
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

print('\nParse request line:')
run("parse_request('GET /foo/bar?stuff=junk HTTP/1.1')")
run("'GET /foo/bar?stuff=junk HTTP/1.1'.split(' ')")
run("'GET' not in {'GET', 'PUT', 'POST', 'DELETE', 'HEAD'}")
run("'/foo/bar?stuff=junk'.startswith('/')")
run("'..' in '/foo/bar?stuff=junk'")
run("'/foo/bar?stuff=junk'.split('?')")
run("'/foo/bar'[1:].split('/')")

print('\nParse status line:')
run("parse_status('HTTP/1.1 404 Not Found')")

print('\nParse Content-Type header:')
run("parse_header('Content-Type: application/json')")
run("'Content-Type: application/json'.split(': ', 1)")
run("'Content-Type'.casefold()")

print('\nParse Content-Length header:')
run("parse_header('Content-Length: 1234567')")
run("'Content-Length: 1234567'.split(': ', 1)")
run("'Content-Length'.casefold()")
run("int('1234567')")

print('-' * 80)

