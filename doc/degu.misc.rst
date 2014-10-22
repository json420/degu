:mod:`degu.misc` --- Unit test helpers
======================================

.. module:: degu.misc
   :synopsis: Test fixtures and other handy tidbits


.. autoclass:: TempPKI



:class:`TempServer` class
-------------------------

.. class:: TempServer(address, app, **options)

    Starts a :class:`degu.server.Server` in a `multiprocessing.Process`_.

    The *address* and *app* arguments, plus any keyword-only *options*, are all
    passed unchanged to the :class:`degu.server.Server` created in the new
    process.

    This background process will be automatically terminated when the
    :class:`TempServer` instance is garbage collected, and can likewise be
    explicitly terminated by calling :meth:`TempServer.terminate()`.

    This class is aimed at unit testing, illustrative documentation, and
    experimenting with the Degu API.  However, it's not the recommended way to
    start an embedded :class:`degu.server.Server` within a production
    application.

    For the production equivalent, please see :class:`degu.EmbeddedServer`.

    .. attribute:: address

        The bound server address as returned by `socket.socket.getsockname()`_.

        Note that this wont necessarily match the *address* argument provided to
        the :class:`TempServer` constructor.

        For details, see the :attr:`degu.server.Server.address` attribute, and
        the server :ref:`server-address` argument.

        :class:`TempServer` uses a `multiprocessing.Queue`_ to pass the bound
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
        :class:`TempServer` constructor, and will not include the default values
        for any other server configuration options.

        For details, see the :attr:`degu.server.Server.options` attribute, and
        the server :ref:`server-options` argument.

    .. attribute:: process

        The `multiprocessing.Process`_ in which this server is running.

    .. method:: terminate()

        Terminate the background process (and thus this Degu server).

        This method will call `multiprocessing.Process.terminate()`_ followed by
        `multiprocessing.Process.join()`_ on the :attr:`TempServer.process` in
        which this background server is running.

        This method is automatically called when the :class:`TempServer`
        instance is garbage collected.  It can safely be called multiple times
        without error.

        If needed, you can inspect the ``exitcode`` attribute on the
        :attr:`TempServer.process` after this method has been called.



:class:`TempSSLServer` class
----------------------------

.. class:: TempSSLServer(sslconfig, address, app, **options)

    Starts a :class:`degu.server.SSLServer` in a `multiprocessing.Process`_.

    The *sslconfig*, *address*, and *app* arguments, plus any keyword-only
    *options*, are all passed unchanged to the :class:`degu.server.SSLServer`
    created in the new process.

    Note that unlike :class:`degu.server.SSLServer`, the first contructor
    argument must be a ``dict`` containing an *sslconfig* as understood by
    :func:`degu.server.build_server_sslctx()`, and cannot be a pre-built
    *sslctx* (an `ssl.SSLContext`_ instance).

    Although not a subclass, this class includes all the same attributes and
    methods as the :class:`TempServer` class, plus adds the
    :attr:`TempSSLServer.sslconfig` attribute.

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
