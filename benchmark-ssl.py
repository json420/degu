#!/usr/bin/python3

import time
import logging
import json

from degu import IPv6_LOOPBACK
from degu.sslhelpers import random_id
from degu.misc import TempPKI, TempSSLServer


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


pki = TempPKI(client_pki=True)
server = TempSSLServer(pki, IPv6_LOOPBACK, None, echo_app)
client = server.get_client()
print(client)

marker = random_id()
body = json.dumps({'ping': marker}).encode()
headers = {
    'content-length': len(body),
    'accept': 'application/json',
    'content-type': 'application/json',
}
count = 10000
deltas = []
for i in range(5):
    client.close()
    start = time.monotonic()
    for i in range(count):
        r = client.request('POST', '/', headers, body)
        assert json.loads(r.body.read().decode()) == {'pong': marker}
    deltas.append(time.monotonic() - start)
client.close()
server.terminate()
delta = min(deltas)
print('{:.2f} requests/second'.format(count / delta))

