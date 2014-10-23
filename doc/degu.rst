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



Functions
---------

.. function:: start_server(address, build_func, *build_args)

    Start a :class:`degu.server.Server` in a new process.

    The return value is a ``(process, address)`` tuple.


.. function:: start_sslserver(sslconfig, address, build_func, *build_args)

    Start a :class:`degu.server.SSLServer` in a new process.

    The return value is a ``(process, address)`` tuple.



Address constants
-----------------

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

    Starts a :class:`degu.server.Server` in a `multiprocessing.Process`_.

    The *address* argument, and any keyword-only *options*, are passed unchanged
    to the :class:`degu.server.Server` created in the new process.

    This background process will be automatically terminated when the
    :class:`EmbeddedServer` instance is garbage collected, and can likewise be
    explicitly terminated by calling :meth:`EmbeddedServer.terminate()`.

    This class is aimed at unit testing, illustrative documentation, and
    experimenting with the Degu API.  However, it's not the recommended way to
    start an embedded :class:`degu.server.Server` within a production
    application.

    For the production equivalent, please see :class:`degu.EmbeddedServer`.

    .. attribute:: address

        The bound server address as returned by `socket.socket.getsockname()`_.

        Note that this wont necessarily match the *address* argument provided to
        the :class:`EmbeddedServer` constructor.

        For details, see the :attr:`degu.server.Server.address` attribute, and
        the server :ref:`server-address` argument.

        :class:`EmbeddedServer` uses a `multiprocessing.Queue`_ to pass the bound
        server address from the newly created background process up to your
        controlling process.

    .. attribute:: app

        The *app* argument provided to the constructor.

        For details, see the the :attr:`degu.server.Server.app` attribute,
        and the server :ref:`server-app` argument.

    .. attribute:: options

        A ``dict`` containing the *options* passed to the constructor.

        Note that unlike :attr:`degu.server.Server.options`, this attribute will
        only contain the keyword-only options specifically provided to the
        :class:`EmbeddedServer` constructor, and will not include the default values
        for any other server configuration options.

        For details, see the :attr:`degu.server.Server.options` attribute, and
        the server :ref:`server-options` argument.

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

    Starts a :class:`degu.server.SSLServer` in a `multiprocessing.Process`_.

    The *sslconfig*, *address*, and *app* arguments, plus any keyword-only
    *options*, are all passed unchanged to the :class:`degu.server.SSLServer`
    created in the new process.

    Note that unlike :class:`degu.server.SSLServer`, the first contructor
    argument must be a ``dict`` containing an *sslconfig* as understood by
    :func:`degu.server.build_server_sslctx()`, and cannot be a pre-built
    *sslctx* (an `ssl.SSLContext`_ instance).

    Although not a subclass, this class includes all the same attributes and
    methods as the :class:`EmbeddedServer` class, plus adds the
    :attr:`EmbeddedSSLServer.sslconfig` attribute.

    This class is aimed at unit testing, illustrative documentation, and
    experimenting with the Degu API.  However, it's not the recommended way to
    start an embedded :class:`degu.server.SSLServer` within a production
    application.

    For the production equivalent, please see :class:`degu.EmbeddedSSLServer`.

    .. attribute:: sslconfig

        The exact *sslconfig* dict passed to the constructor.



.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`multiprocessing.Queue`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Queue
.. _`multiprocessing.Process.terminate()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.terminate
.. _`multiprocessing.Process.join()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.join
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6

