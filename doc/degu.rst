:mod:`degu` - helpers
=====================

.. module:: degu
   :synopsis: multiprocessing helpers and address constants



Functions
---------

.. function:: start_server(address, build_func, *build_args)

    Start a :class:`degu.server.Server` in a new process.

    The return value is a ``(process, address)`` tuple.


.. function:: start_sslserver(sslconfig, address, build_func, *build_args)

    Start a :class:`degu.server.SSLServer` in a new process.

    The return value is a ``(process, address)`` tuple.


Constants
---------

:mod:`degu` includes handy constants with some common IPv6 and IPv4 *address*
tuples:


.. data:: IPv6_LOOPBACK

    A 4-tuple with the IPv6 loopback-only *address*.

    >>> IPv6_LOOPBACK = ('::1', 0, 0, 0)


.. data:: IPv6_ANY

    A 4-tuple with the IPv6 any-IP *address*.

    >>> IPv6_ANY = ('::', 0, 0, 0)

    Note that this address does not allow you to accept connections from
    `link-local addresses`_.


.. data:: IPv4_LOOPBACK

    A 2-tuple with the IPv4 loopback-only *address*.

    >>> IPv4_LOOPBACK = ('127.0.0.1', 0)


.. data:: IPv4_ANY

    A 2-tuple with the IPv4 any-IP *address*.

    >>> IPv4_ANY = ('0.0.0.0', 0)



.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
