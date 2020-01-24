:mod:`degu.misc` --- Test fixtures
==================================

.. module:: degu.misc
   :synopsis: Test fixtures and other handy tidbits

The :mod:`degu.misc` module contains functionality that aids in unit-testing,
demonstration, and play.

Note that production Degu applications are advised *against* importing
``degu.misc`` during normal run-time operation, specifically because it will
make the baseline memory usage of your Degu application larger than needed.


Helper functions
----------------

.. function:: mkreq(method, uri, headers=None, body=None, shift=0)

    Shortcut for making a :class:`degu.server.Request` instance.

    It's rather verbose to create a :class:`degu.server.Request` instance,
    particularly because you must specify both the unparsed URI, and the URI
    as parsed into `mount`, `path`, and `query` components.

    This function greatly simplifies the process and can be quite useful in
    unit-tests.

    Unlike the :class:`degu.server.Request` constructor, only the *method* and
    *uri* arguments are required:

    >>> from degu.misc import mkreq
    >>> mkreq('GET', '/')
    Request(method='GET', uri='/', headers={}, body=None, mount=[], path=[], query=None)

    Note that when the *headers* keyword argument is not provided (or is
    ``None``), this function will create a new, empty ``{}`` for the headers.
    But you can also explicity provide the *headers* to use, for example:

    >>> request = mkreq('GET', '/', headers={'k': 'V'})
    >>> request.headers
    {'k': 'V'}

    Likewise, note that if not provided, the *body* defaults to ``None``.  In
    unit-tests that require an HTTP request body, you'd typically provide a
    suitable :class:`degu.base.Body` or :class:`degu.base.ChunkedBody`
    instance, for example:

    >>> import io
    >>> from degu.base import api
    >>> fp = io.BytesIO(b'hello, world')
    >>> request = mkreq('PUT', '/foo', body=api.Body(fp, 12))
    >>> request.body.read()
    b'hello, world'

    This function will parse the *uri* into RGI ``mount``, ``path``, and
    ``query`` components, for example:

    >>> request = mkreq('GET', '/foo')
    >>> (request.mount, request.path, request.query)
    ([], ['foo'], None)
    >>> request = mkreq('GET', '/foo/bar?key=value')
    >>> (request.mount, request.path, request.query)
    ([], ['foo', 'bar'], 'key=value')

    If the optional *shift* keyword argument is provided, it must be an ``int``
    specifying the number of times that the ``path`` should be shifted to the
    ``mount``.  This emulates one or more calls to
    :meth:`degu.server.Request.shift_path()` as a request is routed to the RGI
    leaf application that will ultimately handle the request.

    For example, when the path is shifted once:

    >>> request = mkreq('GET', '/foo/bar?key=value', shift=1)
    >>> (request.mount, request.path, request.query)
    (['foo'], ['bar'], 'key=value')

    Or when the path is shifted twice:

    >>> request = mkreq('GET', '/foo/bar?key=value', shift=2)
    >>> (request.mount, request.path, request.query)
    (['foo', 'bar'], [], 'key=value')

    This function tries to capture the most common unit-test scenarios as
    concisely as possible, but it may not always be as flexible as you need.
    When more flexibility is needed, please manually construct a
    :class:`degu.server.Request` instance.


.. function:: mkuri(*path, query=None)

    Build an HTTP request URI from RGI *path* and *query* components.

    For example:

    >>> from degu.misc import mkuri
    >>> mkuri('foo', 'bar', query='k=V')
    '/foo/bar?k=V'

    This function provides the inverse of the parsing that will be done by an
    RGI compatible server, and likewise provides the inverse of the parsing
    done by the :func:`mkreq()` helper function.

    This function especially makes it easier to build random request URIs from
    a number of components, for example:

    >>> component = 'my-random-URI-component'
    >>> mkuri('foo', component)
    '/foo/my-random-URI-component'

    This function correctly round-trips the full RGI query semantics, which
    differentiate between no query versus merely an empty query.

    For example, when there's no query:

    >>> mkuri('foo', query=None)
    '/foo'

    When there's an empty query:

    >>> mkuri('foo', query='')
    '/foo?'

    And when there's a non-empty query:

    >>> mkuri('foo', query='hello=world')
    '/foo?hello=world'



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

        Keyword-only *options* provided to the constructor.

        This attribute is mostly aimed at unit testing.  See
        :ref:`server-options` for details.

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

        The exact *sslconfig* ``dict`` passed to the constructor.



:class:`TempPKI`
----------------

.. class:: TempPKI(client_pki=True, bits=2048)

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



Parsing/formatting
------------------

.. function:: parse_headers(src, isresponse=False)

    Parse headers from the ``bytes`` instance *src*.

    .. versionchanged:: 0.16
        This function was moved to the :mod:`degu.misc` module to the
        :mod:`degu.base` module.

    For example:

    >>> from degu.misc import parse_headers
    >>> parse_headers(b'Content-Type: text/plain')
    {'content-type': 'text/plain'}

    Note that although Degu accepts mixed-case headers in the HTTP input
    preamble, they are case-folded when parsed, and that outgoing headers must
    only use lowercase names.

    Because of same details in how the Degu parser works, the function expects
    separate header lines to be separated by a ``b'\r\n'``, but does not allow
    a ``b'\r\n'`` termination after the final header:

    >>> parse_headers(b'Foo: Bar\r\nSTUFF: Junk') == {'foo': 'Bar', 'stuff': 'Junk'}
    True


.. function:: format_headers(headers)

    Format headers for use as the input to :func:`parse_headers()`.

    For example:

    >>> from degu.misc import format_headers
    >>> format_headers({'One': 'two', 'FOO': 'bar'})
    b'FOO: bar\r\nOne: two'

    .. note::

        This is a convenience function aimed at unit testing and benchmarking;
        it does not reflect the behavior of the real Degu backend, which does
        much stricter validation.

    .. versionchanged:: 0.16
        This function was moved to the :mod:`degu.misc` module from the
        :mod:`degu.base` module.


.. function:: format_request(method, uri, headers)

    Format request preamble.

    For example:

    >>> from degu.misc import format_request
    >>> format_request('POST', '/foo', {'Content-Length': 17})
    b'POST /foo HTTP/1.1\r\nContent-Length: 17'

    .. note::

        This is a convenience function aimed at unit testing and benchmarking;
        it does not reflect the behavior of the real Degu backend, which does
        much stricter validation.

    .. versionadded:: 0.17


.. function:: format_response(status, reason, headers)

    Format response preamble.

    For example:

    >>> from degu.misc import format_response
    >>> format_response(200, 'OK', {'Content-Length': 17})
    b'HTTP/1.1 200 OK\r\nContent-Length: 17'

    .. note::

        This is a convenience function aimed at unit testing and benchmarking;
        it does not reflect the behavior of the real Degu backend, which does
        much stricter validation.

    .. versionadded:: 0.17



.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`multiprocessing.Queue`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Queue
.. _`multiprocessing.Process.terminate()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.terminate
.. _`multiprocessing.Process.join()`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process.join
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts

