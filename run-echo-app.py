#!/usr/bin/python3

import logging

from degu import IPv6_LOOPBACK
from degu.client import SSLClient
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

pki = TempPKI()
server = TempSSLServer(pki.server_sslconfig, IPv6_LOOPBACK, echo_app)
client = SSLClient(pki.client_sslconfig, server.address)
conn = client.connect()

headers = {
    'accept': 'application/json',
    'user-agent': 'Degu/1.0',
}
response = conn.request('GET', '/foo/bar?stuff=junk', headers, None)
print(response.body.read().decode())

