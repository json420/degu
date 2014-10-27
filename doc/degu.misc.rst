:mod:`degu.misc` --- Test fixtures
==================================

.. module:: degu.misc
   :synopsis: Test fixtures and other handy tidbits


:class:`TempServer`
-------------------

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



:class:`TempSSLServer`
----------------------

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



:class:`TempPKI`
----------------

.. class:: TempPKI(client_pki=True, bits=1024)

    Creates a throw-away SSL certificate chain.

    For example, simply create a new :class:`TempPKI` instance, and it will
    automatically create a server CA, a server certificate signed by that
    server CA, a client CA, and a client certificate signed by that client CA:

    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()

    **Server sslconfig**

    The :attr:`TempPKI.server_sslconfig` property will return a server-side
    *sslconfig* ``dict``:

    >>> sorted(pki.server_sslconfig)
    ['ca_file', 'cert_file', 'key_file']

    You can pass it to :func:`degu.server.build_server_sslctx()` to build your
    server-side `ssl.SSLContext`_:

    >>> from degu.server import build_server_sslctx
    >>> import ssl
    >>> sslctx = build_server_sslctx(pki.server_sslconfig)
    >>> isinstance(sslctx, ssl.SSLContext)
    True

    You can also provide this *sslconfig* ``dict`` as the first argument when
    creating a :class:`degu.server.SSLServer`, which will automatically call
    :func:`degu.server.build_server_sslctx()` for you:

    >>> from degu.server import SSLServer
    >>> def my_app(session, request, bodies):
    ...     return (200, 'OK', {}, None)
    ... 
    >>> server = SSLServer(pki.server_sslconfig, ('127.0.0.1', 0), my_app)
    >>> isinstance(server.sslctx, ssl.SSLContext)
    True

    **Client sslconfig**

    The :attr:`TempPKI.client_sslconfig` property will return a client-side
    *sslconfig* ``dict``:

    >>> sorted(pki.client_sslconfig)
    ['ca_file', 'cert_file', 'check_hostname', 'key_file']

    You can pass it to :func:`degu.client.build_client_sslctx()` to build your
    client-side `ssl.SSLContext`_:

    >>> from degu.client import build_client_sslctx
    >>> sslctx = build_client_sslctx(pki.client_sslconfig)
    >>> isinstance(sslctx, ssl.SSLContext)
    True

    You can also provide this *sslconfig* ``dict`` as the first argument when
    creating a :class:`degu.client.SSLClient`, which will automatically call
    :func:`degu.client.build_client_sslctx()` for you:

    >>> from degu.client import SSLClient
    >>> def my_app(session, request, bodies):
    ...     return (200, 'OK', {}, None)
    ... 
    >>> client = SSLClient(pki.client_sslconfig, ('127.0.0.1', 12345))
    >>> isinstance(client.sslctx, ssl.SSLContext)
    True

    **Anonymous server sslconfig**

    The :attr:`TempPKI.anonymous_server_sslconfig` property returns a
    server-side *sslconfig* that will allow connections from unauthenticated
    clients.  Great care must be taken when using a configuration like this, and
    this is not the typical way you'd configure your Degu server in a production
    application.

    Compared to :attr:`TempPKI.server_sslconfig`, the ``'ca_file'`` is removed,
    and the special ``'allow_unauthenticated_clients'`` flag is added:

    >>> sorted(pki.anonymous_server_sslconfig)
    ['allow_unauthenticated_clients', 'cert_file', 'key_file']
    >>> pki.anonymous_server_sslconfig['allow_unauthenticated_clients']
    True

    The ``'allow_unauthenticated_clients'`` flag is to make the API more
    explicit, so that one can't accidentally allow unathenticated clients by
    merely ommitting the ``'ca_file'``.

    (See :func:`degu.server.build_server_sslctx()` for more details.)

    **Anonymous client sslconfig**

    The :attr:`TempPKI.anonymous_client_sslconfig` property will return a
    client-side *sslconfig* ``dict`` that will still authenticate the server,
    but will not provide a certificate by which the server can authenticate the
    client.

    Compared to :attr:`TempPKI.client_sslconfig`, the ``'cert_file'`` and
    ``'key_file'`` are removed:

    >>> sorted(pki.anonymous_client_sslconfig)
    ['ca_file', 'check_hostname']


    .. attribute:: server_sslconfig

        This property returns a copy of the server *sslconfig*.

        Example value::
        
            {
                'ca_file': '/tmp/TempPKI.7m8pjsye/MDKJWRMDYNQVYS3HTUIDPKEUWIC6KVOHW4XU54IAISC6WLET.ca',
                'cert_file': '/tmp/TempPKI.7m8pjsye/VXE7IRVLUZZIDKCFK6RF3DCRQ55GC6OI7Y2XRB2EQNQBLQYI.cert',
                'key_file': '/tmp/TempPKI.7m8pjsye/VXE7IRVLUZZIDKCFK6RF3DCRQ55GC6OI7Y2XRB2EQNQBLQYI.key',
            }


    .. attribute:: client_sslconfig

        This property returns a copy of the client *sslconfig*.

        Example value::

            client_sslconfig
            {
                'ca_file': '/tmp/TempPKI.7m8pjsye/ONF7MOFOPPTWFWYJLWR4MMR2PD472MU3MOZHFXLSYM7DCJ2A.ca',
                'cert_file': '/tmp/TempPKI.7m8pjsye/QBOBCGIXQ3ZG555ZJD36TX4QUWRLFBM2RPKJJ2VHZHAAGTPH.cert',
                'check_hostname': False,
                'key_file': '/tmp/TempPKI.7m8pjsye/QBOBCGIXQ3ZG555ZJD36TX4QUWRLFBM2RPKJJ2VHZHAAGTPH.key',
            }


    .. attribute:: anonymous_server_sslconfig

        This property returns a copy of the anonymous server *sslconfig*.

        Example value::

            {
                'allow_unauthenticated_clients': True,
                'cert_file': '/tmp/TempPKI.7m8pjsye/VXE7IRVLUZZIDKCFK6RF3DCRQ55GC6OI7Y2XRB2EQNQBLQYI.cert',
                'key_file': '/tmp/TempPKI.7m8pjsye/VXE7IRVLUZZIDKCFK6RF3DCRQ55GC6OI7Y2XRB2EQNQBLQYI.key',
            }


    .. attribute:: anonymous_client_sslconfig

        This property returns a copy of the anonymous client *sslconfig*.

        Example value::

            anonymous_client_sslconfig
            {
                'ca_file': '/tmp/TempPKI.7m8pjsye/ONF7MOFOPPTWFWYJLWR4MMR2PD472MU3MOZHFXLSYM7DCJ2A.ca',
                'check_hostname': False,
            }



.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`multiprocessing.Queue`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Queue
.. _`multiprocessing.Process.terminate()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.terminate
.. _`multiprocessing.Process.join()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.join
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
