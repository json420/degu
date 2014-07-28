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


def ping_pong_app(connection, request):
    request['body'].read()
    #assert json.loads(data.decode()) == {'ping': ping}
    headers = {
        'content-type': 'application/json',
        'server': agent,
    }
    return (200, 'OK', headers, response_body)


if args.unix:
    tmp = TempDir()
    address = tmp.join('my.socket')
else:
    address = degu.IPv6_LOOPBACK
server = TempServer(address, None, ping_pong_app)
client = Client(server.address)


headers = {
    'accept': 'application/json',
    'content-type': 'application/json',
    'user-agent': agent
}
count = 5000
deltas = []
for i in range(15):
    conn = client.connect()
    start = time.monotonic()
    for i in range(count):
        conn.request('POST', '/', headers, request_body).body.read()
        #assert json.loads(data.decode()) == {'pong': pong}
    deltas.append(time.monotonic() - start)
    conn.close()
server.terminate()

rates = tuple(count / d for d in deltas)
fastest = '{:.2f}'.format(max(rates))
stdev = '{:.2f}'.format(statistics.stdev(rates))
width = max(len(fastest), len(stdev))

print('')
print('fastest: {} requests/second'.format(fastest.rjust(width)))
print('  stdev: {} requests/second'.format(stdev.rjust(width)))
