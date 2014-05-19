#!/usr/bin/python3

import time
import logging
import json
import argparse

from degu import IPv6_LOOPBACK
from degu.sslhelpers import random_id
from degu.misc import TempServer
from degu.tests.helpers import TempDir


parser = argparse.ArgumentParser()
parser.add_argument('--unix', action='store_true', default=False,
    help='Use AF_UNIX instead of AF_INET6'
)
args = parser.parse_args()


logging.basicConfig(
    level=logging.DEBUG,
    format='\t'.join([
        '%(levelname)s',
        '%(processName)s',
        '%(threadName)s',
        '%(message)s',
    ]),
)
log = logging.getLogger()


def echo_app(request):
    data = request['body'].read()
    obj = json.loads(data.decode())
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
    address = IPv6_LOOPBACK
server = TempServer(address, None, echo_app)
client = server.get_client()
print(client)


marker = random_id(60)
body = json.dumps({'ping': marker}).encode()
headers = {
    'content-length': len(body),
    'accept': 'application/json',
    'content-type': 'application/json',
}


count = 10000
deltas = []
for i in range(5):
    start = time.monotonic()
    conn = client.connect()
    for i in range(count):
        r = conn.request('POST', '/', headers, body)
        assert json.loads(r.body.read().decode()) == {'pong': marker}
    deltas.append(time.monotonic() - start)
    conn.close()
server.terminate()
delta = min(deltas)
print('{:.2f} requests/second'.format(count / delta))


