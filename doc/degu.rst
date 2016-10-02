:mod:`degu` --- Embedding helpers
=================================

.. module:: degu
   :synopsis: helper functions for embedding Degu in other applications

The top-level :mod:`degu` package contains just a few functions for helping
applications launch an embedded :class:`degu.server.Server` or
:class:`degu.server.SSLServer` in its own `multiprocessing.Process`_.

Importing :mod:`degu` does not cause any Degu sub-modules, nor any of their
dependencies, to be imported.  The needed Degu sub-modules and dependencies are
lazily imported only within a newly spawned `multiprocessing.Process`_.

This means that importing :mod:`degu` has an extremely minimal impact on the
memory footprint of your main application process.  This is especially useful
for applications that may not always run a Degu server, or that only run a Degu
server for a limited period of time after which the Degu server is shutdown.



*address* constants
-------------------

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


:class:`EmbeddedServer`
-----------------------

.. class:: EmbeddedServer(address, build_func, *build_args, **options)

    Starts a :class:`degu.server.Server` in a new `multiprocessing.Process`_.

    The *address* argument, and any keyword-only *options*, are passed unchanged
    to the :class:`degu.server.Server` created in the new process.

    Your *build_func* will be called with *build_args* in the new process to
    create your application, something like this::

        from degu.server import Server
        app = build_func(*build_args)
        server = Server(address, app, **options)

    :meth:`EmbeddedServer.terminate()` will be automatically called when an
    instance is garbage collected.


    .. attribute:: address

        The bound server address as returned by `socket.socket.getsockname()`_.

        Note that this wont necessarily match the *address* argument provided to
        the :class:`EmbeddedServer` constructor.

        For details, see the :attr:`degu.server.Server.address` attribute, and
        the server :ref:`server-address` argument.

        :class:`EmbeddedServer` uses a `multiprocessing.Queue`_ to pass the
        bound server address from the newly created background process up to
        your controlling process.


    .. attribute:: build_func

        The *build_func* argument provided to the constructor.


    .. attribute:: build_args

        A ``tuple`` containing any *build_args* passed to the constructor.


    .. attribute:: options

        A ``dict`` containing any *options* passed to the constructor.


    .. attribute:: process

        The `multiprocessing.Process`_ in which this server is running.

    .. method:: terminate()

        Terminate the background process (and thus this Degu server).

        This method will call `multiprocessing.Process.terminate()`_ followed by
        `multiprocessing.Process.join()`_ on the :attr:`EmbeddedServer.process` in
        which this background server is running.

        This method is automatically called when the :class:`EmbeddedServer`
        instance is garbage collected.  It can safely be called multiple times
        without error.

        If needed, you can inspect the ``exitcode`` attribute on the
        :attr:`EmbeddedServer.process` after this method has been called.



:class:`EmbeddedSSLServer`
--------------------------

.. class:: EmbeddedSSLServer(sslconfig, address, build_func, *build_args, **options)

    Starts a :class:`degu.server.SSLServer` in a new `multiprocessing.Process`_.

    The *sslconfig* and *address* arguments, plus any keyword-only *options*,
    are all passed unchanged to the :class:`degu.server.SSLServer` created in
    the new process.

    Your *build_func* will be called with *build_args* in the new process to
    create your application, something like this::

        from degu.server import SSLServer
        app = build_func(*build_args)
        server = SSLServer(sslconfig, address, app, **options)

    Although not a subclass, this class includes all the same attributes and
    methods as the :class:`EmbeddedServer` class, plus adds the
    :attr:`EmbeddedSSLServer.sslconfig` attribute.


    .. attribute:: sslconfig

        The *sslconfig* argument provided to the constructor.




.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`multiprocessing.Queue`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Queue
.. _`multiprocessing.Process.terminate()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.terminate
.. _`multiprocessing.Process.join()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.join
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`link-local addresses`: https://en.wikipedia.org/wiki/Link-local_address#IPv6

