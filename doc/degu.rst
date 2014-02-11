:mod:`degu` API
===============

.. py:module:: degu
    :synopsis: an embedded HTTP server and client library



:mod:`degu.server` --- HTTP Server
----------------------------------

.. module:: degu.server
   :synopsis: Embedded HTTP Server

Both :class:`Server` and :class:`SSLServer` take an *address* argument, which
must be a 4-tuple for IPv6 and a 2-tuple for IPv4.  This *address* argument is
passed directly to `socket.bind()`_, thereby giving you access to full IPv6
address semantics, including the *scopeid* needed for `link-local addresses`_.

Note that although Python's `socket.bind()`_ will accept a 2-tuple for an
``AF_INET6`` family socket (IPv6), Degu does not allow this.  An IPv6 *address*
must always be a 4-tuple.  This restriction gives Degu a simple, unambiguous way
of selecting between ``AF_INET6`` and ``AF_INET``, without needing to inspect
``address[0]`` (the host portion).

:mod:`degu.server` includes handy constants with some common IPv6 and IPv4
*address* tuples:

.. data:: IPv6_LOOPBACK

    A 4-tuple with the IPv6 loopback-only *address*.

    >>> IPv6_LOOPBACK = ('::1', 0, 0, 0)


.. data:: IPv6_ANY

    A 4-tuple with the IPv6 any-IP address.

    >>> IPv6_ANY = ('::', 0, 0, 0)

    Note that this address does not allow you to accept connections from
    `link-local addresses`_.


.. data:: IPv4_LOOPBACK

    A 2-tuple with the IPv4 loopback-only address.

    >>> IPv4_LOOPBACK = ('127.0.0.1', 0)


.. data:: IPv4_ANY

    A 4-tuple with the IPv4 any-IP address.

    >>> IPv4_ANY = ('0.0.0.0', 0)



.. class:: Server(address, app)

    .. attribute:: sock

        The ``socket.socket`` instance upon which the server is listening.

    .. attribute:: address

        The address as returned by ``getsockname()`` on the above :attr:`sock`.

        Note this wont necessarily match the *address* provided when the
        instance was created.  As Degu is designed for per-user server instances
        on dynamic ports, you typically specify port ``0`` in the *address*,
        using something like this::

            ('::', 0, 0, 0)

        In which case this address attribute will contain the random port
        assigned by the operating system, something like this::

            ('::', 40505, 0, 0)

    .. attribute:: app

        The :doc:`rgi` application provided when the instance was created.



.. class:: SSLServer(sslctx, addresss, app)



:mod:`degu.client` --- HTTP Client
----------------------------------

.. module:: degu.client
   :synopsis: Low-level HTTP client


.. class:: Client(address, headers=None)

    .. method:: request(method, uri, headers=None, body=None)

.. class:: SSLClient(sslctx, address, headers=None)



.. _`socket.bind()`: http://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
