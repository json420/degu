#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from collections import namedtuple
from degu._basepy import Response as Response1
from degu._base import Response as Response2
Request = namedtuple('Request', 'method uri script path query headers')

r1 = {
    'method': 'GET',
    'uri': '/foo/bar?stuff=junk',
    'script': [],
    'path': ['foo', 'bar'],
    'query': 'stuff=junk',
    'headers': {},
}

r2 = ('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {})
r3 = Request('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {})


v1 = Response1(200, 'OK', {}, None)
v2 = Response2(200, 'OK', {}, None)

"""


def run_iter(statement, n):
    for i in range(10):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=1000):
    n = K * 1000
    # Choose fastest of 10 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>11,}: {}'.format(rate, statement))
    return rate


print('-' * 80)
run("r1['method']")
run('r2[0]')
run('r3[0]')
run('r3.method')
run("r1['uri']")
run('r2[1]')
run('r3[1]')
run('r3.uri')

print('')
run("Response1(200, 'OK', {}, None)")
run("Response2(200, 'OK', {}, None)")

print('')
run('v1.status')
run('v1.reason')
run('v1.headers')
run('v1.body')

print('')
run('v2.status')
run('v2.reason')
run('v2.headers')
run('v2.body')

print('-' * 80)

