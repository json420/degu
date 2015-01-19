#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from io import BytesIO

from degu._base import (
    format_headers,
    format_request_preamble,
    format_response_preamble,

    parse_content_length,
    parse_request_line,
    parse_method,
    parse_uri,
    parse_request,
    parse_response_line,
    parse_response,
)


headers = {
    'content-type': 'application/json',
    'accept': 'application/json',
    'content-length': 12,
    'user-agent': 'Microfiber/14.12.0 (Ubuntu 14.04; x86_64)',
    'x-token': 'VVI5KPPRN5VOG9DITDLEOEIB',
    'extra': 'Super',
    'hello': 'World',
    'k': 'V',
}
request = format_request_preamble('POST', '/foo/bar?stuff=junk', headers)[:-4]
response = format_response_preamble(200, 'OK', headers)[:-4]
"""


def run_iter(statement, n):
    for i in range(10):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=250):
    n = K * 1000
    # Choose fastest of 10 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>11,}: {}'.format(rate, statement))
    return rate


print('-' * 80)

run('parse_request(request)')
run('parse_response(response)')

raise SystemExit()

print('\nCommon formatting:')
run('format_headers(headers)')

print('\nRequest formatting:')
run("format_request_preamble('GET', '/foo', {})")
run("format_request_preamble('PUT', '/foo', {'content-length': 17})")
run("format_request_preamble('PUT', '/foo', headers)")

print('\nResponse formatting:')
run("format_response_preamble(200, 'OK', {})")
run("format_response_preamble(200, 'OK', {'content-length': 17})")
run("format_response_preamble(200, 'OK', headers)")

print('\nCommon parsing:')
run("parse_content_length(b'9007199254740992')")

print('\nRequest parsing:')
run("parse_request(b'GET / HTTP/1.1')")
run("parse_request(b'DELETE /foo/bar?stuff=junk HTTP/1.1')")
run("parse_request(b'GET / HTTP/1.1\\r\\ncontent-length: 17')")
run("parse_request_line(b'GET / HTTP/1.1')")
run("parse_request_line(b'DELETE /foo/bar?stuff=junk HTTP/1.1')")
run("parse_method(b'GET')")
run("parse_method(b'PUT')")
run("parse_method(b'POST')")
run("parse_method(b'HEAD')")
run("parse_method(b'DELETE')")
run("parse_uri(b'/')")
run("parse_uri(b'/?')")
run("parse_uri(b'/foo/bar')")
run("parse_uri(b'/foo/bar?stuff=junk')")

print('\nResponse parsing:')
run("parse_response_line(b'HTTP/1.1 200 OK')")
run("parse_response_line(b'HTTP/1.1 404 Not Found')")
run('parse_response(response)')

print('-' * 80)

