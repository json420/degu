#!/usr/bin/python3

import time
import logging
import json
import multiprocessing

from dbase32 import random_id

from degu.misc import TempPKI
from degu.client import SSLClient, build_client_sslctx
from degu.server import SSLServer, build_server_sslctx


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


def start_process(target, *args, **kw):
    process = multiprocessing.Process(target=target, args=args, kwargs=kw)
    process.daemon = True
    process.start()
    return process


def run_server(queue, sslconfig, app, bind_address='::1', port=0):
    try:
        sslctx = build_server_sslctx(sslconfig)
        httpd = SSLServer(sslctx, app, bind_address, port)
        env = {'port': httpd.port, 'url': httpd.url}
        queue.put(env)
        httpd.serve_forever()
    except Exception as e:
        queue.put(e)


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
q = multiprocessing.Queue()
start_process(run_server, q, pki.server_config, echo_app)
env = q.get()
print(env)


marker = random_id()
body = json.dumps({'ping': marker}).encode('utf-8')
headers = {
    'content-length': len(body),
    'accept': 'application/json',
    'content-type': 'application/json',
}
sslctx = build_client_sslctx(pki.client_config)
client = SSLClient(sslctx, '::1', env['port'], check_hostname=False)
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

