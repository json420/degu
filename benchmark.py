#!/usr/bin/python3

import time
import logging
import json
import argparse
import statistics

import degu
from degu.sslhelpers import random_id
from degu.misc import TempServer
from degu.tests.helpers import TempDir
from degu.client import Client


parser = argparse.ArgumentParser()
parser.add_argument('--unix', action='store_true', default=False,
    help='Use AF_UNIX instead of AF_INET6'
)
parser.add_argument('--requests', type=int, default=10000,
    help='number of requests per connection'
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


agent = 'Degu/{}'.format(degu.__version__)
ping = random_id(60)
request_body = json.dumps({'ping': ping}).encode()
pong = random_id(60)
response_body = json.dumps({'pong': pong}).encode()


def ping_pong_app(session, request, bodies):
    request['body'].read()
    #assert json.loads(data.decode()) == {'ping': ping}
    return (200, 'OK', {}, response_body)


if args.unix:
    tmp = TempDir()
    address = tmp.join('my.socket')
else:
    address = degu.IPv6_LOOPBACK
server = TempServer(address, ping_pong_app, max_requests=args.requests)
client = Client(server.address)

count = args.requests
deltas = []
for i in range(10):
    conn = client.connect()
    start = time.monotonic()
    for i in range(count):
        conn.request('POST', '/', {}, request_body).body.read()
        #assert json.loads(data.decode()) == {'pong': pong}
    deltas.append(time.monotonic() - start)
    conn.close()
server.terminate()

rates = tuple(count / d for d in deltas)
fastest = '{:.2f}'.format(max(rates))
mean = '{:.2f}'.format(statistics.mean(rates))
stdev = '{:.2f}'.format(statistics.stdev(rates))
width = max(len(fastest), len(mean), len(stdev))

print('')
print('run {} of {} was fastest'.format(rates.index(max(rates)) + 1, len(rates)))
print('fastest: {} requests/second'.format(fastest.rjust(width)))
print('average: {} requests/second'.format(mean.rjust(width)))
print('  stdev: {} requests/second'.format(stdev.rjust(width)))
