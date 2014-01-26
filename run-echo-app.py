#!/usr/bin/python3

import time
import logging
import json

from degu.client import Client
from degu.misc import echo_app
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


(httpd, env) = start_server(echo_app)
client = Client('::1', env['port'])
response = client.request('GET', '/foo/bar?stuff=junk',
    {'accept': 'application/json', 'user-agent': 'Microfiber/14.04'}
)
print(response.body.read().decode())

httpd.terminate()
httpd.join()
