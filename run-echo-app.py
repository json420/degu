#!/usr/bin/python3

import time
import logging
import json

from degu.misc import TempPKI, TempSSLServer, echo_app


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

pki = TempPKI(True)
httpd = TempSSLServer(pki, None, echo_app)
client = httpd.get_client()
response = client.request('GET', '/foo/bar?stuff=junk',
    {'accept': 'application/json', 'user-agent': 'Microfiber/14.04'}
)
print(response.body.read().decode())

