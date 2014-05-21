#!/usr/bin/python3

import logging

from degu import IPv6_LOOPBACK
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
httpd = TempSSLServer(pki, IPv6_LOOPBACK, None, echo_app)
client = httpd.get_client()
conn = client.connect()
response = conn.request('GET', '/foo/bar?stuff=junk',
    {'accept': 'application/json', 'user-agent': 'Microfiber/14.04'}
)
print(response.body.read().decode())

