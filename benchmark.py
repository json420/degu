#!/usr/bin/python3

import time
import logging
import json
import argparse
import statistics
import platform
import sys

import degu
from degu.sslhelpers import random_id
from degu.misc import TempServer
from degu.tests.helpers import TempDir
from degu.client import Client


REQUESTS = 10000
RUNS = 20

parser = argparse.ArgumentParser()
parser.add_argument('--json', action='store_true', default=False,
    help='Output result in machine-readable JSON'
)
parser.add_argument('--send-host', action='store_true', default=False,
    help='Send an HTTP Host header for AF_INET6'
)
parser.add_argument('--unix', action='store_true', default=False,
    help='Use AF_UNIX instead of AF_INET6'
)
parser.add_argument('--requests', type=int, metavar='N', default=REQUESTS,
    help='Number of requests per run; default={}'.format(REQUESTS)
)
parser.add_argument('--runs', type=int, metavar='N', default=RUNS,
    help='Number of runs; default={}'.format(RUNS)
)
args = parser.parse_args()


logging.basicConfig(
    level=logging.DEBUG,
    format='\t'.join([
        '%(levelname)s',
        '%(threadName)s',
        '%(message)s',
    ]),
)

ping = random_id(60)
request_body = json.dumps({'ping': ping}).encode()
pong = random_id(60)
response_body = json.dumps({'pong': pong}).encode()


def ping_pong_app(session, request, bodies):
    request.body.read()
    return (200, 'OK', {}, response_body)


if args.unix:
    tmp = TempDir()
    address = tmp.join('my.socket')
else:
    tmp = None
    address = degu.IPv6_LOOPBACK
server = TempServer(address, ping_pong_app, max_requests=args.requests)
if args.send_host:
    client = Client(server.address)
else:
    client = Client(server.address, host=None)


deltas = []
for i in range(args.runs):
    conn = client.connect()
    start = time.monotonic()
    for i in range(args.requests):
        conn.post('/', {}, request_body).body.read()
    deltas.append(time.monotonic() - start)
    conn.close()
del tmp
server.terminate()

rates = tuple(args.requests / d for d in deltas)
_max = max(rates)
_mean = statistics.mean(rates)
_min = min(rates)
_stdev = statistics.stdev(rates)
pyinfo = '{}; {}; {} ({} {})'.format(
    platform.python_version(),
    platform.machine(),
    platform.system(),
    platform.dist()[0],
    platform.dist()[1],
)
family = ('AF_UNIX' if args.unix else 'AF_INET6')
if args.json:
    doc = {
        'Degu': degu.__version__,
        'Python': pyinfo,
        'family': family,
        'requests': args.requests,
        'runs': args.runs,
        'fastest': _max,
        'average': _mean,
        'slowest': _min,
        'stdev': _stdev,
    }
    print(json.dumps(doc, sort_keys=True, indent=4))
    sys.exit(0)

fastest_run = str(rates.index(_max) + 1)
slowest_run = str(rates.index(_min) + 1)
width1 = max(len(s) for s in [fastest_run, slowest_run])

fastest = '{:,.0f}'.format(_max)
mean = '{:,.0f}'.format(_mean)
slowest = '{:,.0f}'.format(_min)
stdev = '{:,.0f}'.format(_stdev)
width2 = max(len(s) for s in [fastest, mean, slowest, stdev])

print('')
print('Degu: {}'.format(degu.__version__))
print('Python: {}'.format(pyinfo))
print('Test: {}; {:,} requests per run; {} runs'.format(
    family, args.requests, args.runs)
)
print('Request body: {:d} bytes'.format(len(request_body)))
print('Response body: {:d} bytes'.format(len(response_body)))
print('-' * 72)
print('Run {} of {} was fastest'.format(fastest_run.rjust(width1), args.runs))
print('Run {} of {} was slowest'.format(slowest_run.rjust(width1), args.runs))
print('Requests per second:')
print('    fastest: {}'.format(fastest.rjust(width2)))
print('    average: {}'.format(mean.rjust(width2)))
print('    slowest: {}'.format(slowest.rjust(width2)))
print('      stdev: {}'.format(stdev.rjust(width2)))
print('-' * 72)

