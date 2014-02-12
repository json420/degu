:mod:`degu.client` --- HTTP Client
==================================

.. module:: degu.client
   :synopsis: Low-level HTTP client


Connection *address*
--------------------

Both :class:`Client` and :class:`SSLClient` take an *address* argument, which
can be a ``(host, port)`` 2-tuple or a ``(host, port, flowinfo, scopeid)``
4-tuple.

If your *address* is a ``(host, port)`` 2-tuple, it's passed directly to
`socket.create_connection()`_ when creating a connection.  The *host* can be an
IPv6 IP, an IPv4 IP, or a DNS name.  For example, these are all valid 2-tuple
*address* values::

    ('2001:4860:4860::8888', 80)
    ('8.8.8.8', 80)
    ('www.example.com', 80)

If your *address* is a ``(host, port, flowinfo, scopeid)`` 4-tuple, it's passed
directly to `socket.socket.connect()`_ when creating a connection, thereby
giving you access to full IPv6 address semantics, including the *scopeid* needed
for `link-local addresses`_.  In this case the *host* must be an IPv6 IP.  For
example, this *address* would connect to a server listening on a link-local
address:

    ('fe80::e8b:fdff:fe75:402c', 80, 0, 3)



The :class:`Client` class
-------------------------

.. class:: Client(address, default_headers=None)

    .. method:: request(method, uri, headers=None, body=None)


The :class:`SSLClient` class
----------------------------

.. class:: SSLClient(sslctx, address, default_headers=None)



.. _`socket.create_connection()`: http://docs.python.org/3/library/socket.html#socket.create_connection
.. _`socket.socket.connect()`: http://docs.python.org/3/library/socket.html#socket.socket.connect
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
