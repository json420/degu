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


def ping_pong_app(connection, request):
    obj = json.loads(request['body'].read().decode())
    body = json.dumps({'pong': obj['ping']}).encode()
    headers = {
        'content-length': len(body),
        'content-type': 'application/json',
    }
    return (200, 'OK', headers, body)


if args.unix:
    tmp = TempDir()
    address = tmp.join('my.socket')
else:
    address = degu.IPv6_LOOPBACK
server = TempServer(address, None, ping_pong_app)
client = Client(server.address)


marker = random_id(60)
body = json.dumps({'ping': marker}).encode()
headers = {
    'content-length': len(body),
    'accept': 'application/json',
    'content-type': 'application/json',
    'user-agent': 'Degu/{}'.format(degu.__version__),
}


count = 5000
deltas = []
for i in range(15):
    start = time.monotonic()
    conn = client.connect()
    for i in range(count):
        data = conn.request('POST', '/', headers, body).body.read()
        assert json.loads(data.decode()) == {'pong': marker}
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
