#!/usr/bin/python3

import timeit

setup = """
gc.enable()

from degu._basepy import Response as Response1
from degu._basepy import Request as Request1
from degu._base import Response as Response2
from degu._base import Request as Request2

req0 = {
    'method': 'GET',
    'uri': '/foo/bar?stuff=junk',
    'script': [],
    'path': ['foo', 'bar'],
    'query': 'stuff=junk',
    'headers': {},
    'body': None,
}
req1 = Request1('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {}, None)
req2 = Request2('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {}, None)

rsp1 = Response1(200, 'OK', {}, None)
rsp2 = Response2(200, 'OK', {}, None)
"""


def run_iter(statement, n):
    for i in range(10):
        t = timeit.Timer(statement, setup)
        yield t.timeit(n)


def run(statement, K=500):
    n = K * 1000
    # Choose fastest of 10 runs:
    elapsed = min(run_iter(statement, n))
    rate = int(n / elapsed)
    print('{:>11,}: {}'.format(rate, statement))
    return rate


print('-' * 80)

print('Creating request objects:')
run("{'method':'GET','uri':'/foo/bar?stuff=junk','script':[],'path':['foo','bar'],'query':'stuff=junk','headers':{},'body':None}")
run("Request1('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {}, None)")
run("Request2('GET', '/foo/bar?stuff=junk', [], ['foo', 'bar'], 'stuff=junk', {}, None)")

print('\nAccessing request items:')
run("req0['method']")
run('req1[0]')
run('req1.method')
run('req2[0]')
run('req2.method')

print('\nCreating response objects:')
run("Response1(200, 'OK', {}, None)")
run("Response2(200, 'OK', {}, None)")

print('\nAccessing response items')
run('rsp1[0]')
run('rsp1.status')
run('rsp2[0]')
run('rsp2.status')

print('-' * 80)

