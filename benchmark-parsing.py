#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from io import BytesIO

from degu._base import (
    parse_headers,
    parse_content_length,
    parse_range,
    parse_content_range,

    parse_request,
    parse_request_line,
    parse_method,
    parse_uri,

    parse_response,
    parse_response_line,

    render_headers,
    render_request,
    render_response,

    parse_chunk_size,
    parse_chunk,
)
from degu.misc import format_headers, format_request, format_response


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
headers_src = format_headers(headers)
request_src = format_request('POST', '/foo/bar?stuff=junk', headers)
response_src = format_response(200, 'OK', headers)

dst = memoryview(bytearray(4096))
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


# FIXME: not currently used, but likely will be in the future
def compare(s1, s2, K=100):
    r1 = run(s1, K)
    r2 = run(s2, K)
    percent = (r1 / r2 * 100) - 100
    print('  [{:.1f}%]\n'.format(percent))
    return percent


print('\nHeader parsing:')
run('parse_headers(headers_src)')
run("parse_headers(b'Content-Length: 123456')")
run("parse_headers(b'Transfer-Encoding: chunked')")
run("parse_headers(b'Content-Length: 123456\\r\\nContent-Type: application/json')")
run("parse_headers(b'Transfer-Encoding: chunked\\r\\nContent-Type: application/json')")
run("parse_content_length(b'0')")
run("parse_content_length(b'9999999999999999')")
run("parse_range(b'bytes=0-0')")
run("parse_range(b'bytes=9999999999999998-9999999999999998')")
run("parse_content_range(b'bytes 0-0/1')")
run("parse_content_range(b'bytes 9999999999999998-9999999999999998/9999999999999999')")

print('\nRequest parsing:')
run('parse_request(request_src, BytesIO())')
run("parse_request(b'GET / HTTP/1.1', BytesIO())")
run("parse_request(b'DELETE /foo/bar?stuff=junk HTTP/1.1', BytesIO())")
run("parse_request(b'POST / HTTP/1.1\\r\\ncontent-length: 17', BytesIO())")
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
run("parse_response('GET', response_src, BytesIO())")
run("parse_response_line(b'HTTP/1.1 200 OK')")
run("parse_response_line(b'HTTP/1.1 404 Not Found')")

print('\nChunk parsing:')
run("parse_chunk_size(b'0')")
run("parse_chunk_size(b'1000000')")
run("parse_chunk(b'0')")
run("parse_chunk(b'1000000')")
run("parse_chunk(b'0;key=value')")
run("parse_chunk(b'1000000;key=value')")

print('\nHeader rendering:')
run('render_headers(dst, headers)')
run('render_headers(dst, {})')
run("render_headers(dst, {'content-length': 17})")
run("render_headers(dst, {'content-length': 17, 'content-type': 'text/plain'})")

print('\nRequest rendering:')
run("render_request(dst, 'GET', '/foo', {})")
run("render_request(dst, 'PUT', '/foo', {'content-length': 17})")
run("render_request(dst, 'PUT', '/foo', headers)")

print('\nResponse rendering:')
run("render_response(dst, 200, 'OK', {})")
run("render_response(dst, 200, 'OK', {'content-length': 17})")
run("render_response(dst, 200, 'OK', headers)")

print('-' * 80)

