#!/usr/bin/python3

import time
import logging
import json

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
    obj = json.loads(data.decode('utf-8'))
    body = json.dumps({'pong': obj['ping']}).encode('utf-8')
    headers = {
        'content-length': len(body),
        'content-type': 'application/json',
    }
    return (200, 'OK', headers, body)


pki = TempPKI(client_pki=True)
server = TempSSLServer(pki, None, echo_app)
client = server.get_client()
print(client)

marker = random_id()
body = json.dumps({'ping': marker}).encode('utf-8')
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
        assert json.loads(r.body.read().decode('utf-8')) == {'pong': marker}
    deltas.append(time.monotonic() - start)
delta = min(deltas)
print('{:.2f} requests/second'.format(count / delta))

