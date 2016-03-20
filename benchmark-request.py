#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from degu.server import Request
from degu.util import relative_uri


r1 = Request('GET', '/foo/bar?k=v', {}, None, [], ['foo', 'bar'], 'k=v')
r2 = Request('GET', '/foo/bar', {}, None, [], ['foo', 'bar'], None)
"""


def run_iter(statement, n):
    for i in range(10):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=750):
    n = K * 1000
    # Choose fastest of 10 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>11,}: {}'.format(rate, statement))
    return rate


run('relative_uri(r1)')
run('relative_uri(r2)')
run('r1.build_proxy_uri()')
run('r2.build_proxy_uri()')

