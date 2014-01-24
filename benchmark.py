#!/usr/bin/python3

import time
import logging
import json

from dbase32 import random_id

from degu.client import Client
from degu.server import start_server


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


(httpd, env) = start_server(echo_app)


marker = random_id(60)
body = json.dumps({'ping': marker}).encode('utf-8')
headers = {
    'content-length': len(body),
    'accept': 'application/json',
    'content-type': 'application/json',
}

client = Client('::1', env['port'])
count = 10000
deltas = []
for i in range(5):
    start = time.monotonic()
    for i in range(count):
        r = client.request('POST', '/', headers, body)
        assert json.loads(r.body.read().decode('utf-8')) == {'pong': marker}
    deltas.append(time.monotonic() - start)
    client.close()
delta = min(deltas)
print('{:.2f} requests/second'.format(count / delta))

httpd.terminate()
httpd.join()
