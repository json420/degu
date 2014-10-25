:mod:`degu.client` --- HTTP Client
==================================

.. module:: degu.client
   :synopsis: Low-level HTTP client

The :mod:`degu.client` module provides a low-level HTTP/1.1 client library.

It's similar in abstraction level to the `http.client`_ module in the Python3
standard library, and has an API that overall should feel familiar to those
experienced with `http.client`_ (although there are some major differences, for
details see :ref:`degu-client-v-http-client`).

As a quick example, say we define this Degu server application and run it
in a :class:`degu.misc.TempServer`:

>>> def example_app(session, request, bodies):
...     return (200, 'OK', {'x-msg': 'hello, world'}, None)
...
>>> from degu.misc import TempServer
>>> server = TempServer(('127.0.0.1', 0), example_app)

A :class:`Client` specifies *how* to connect to an HTTP server.

Create a :class:`Client` like this:

>>> from degu.client import Client
>>> client = Client(server.address)

On the other hand, a :class:`Connection` represents a specific TCP connection to
said server, through which one or more HTTP requests can be made.

Create a :class:`Connection` using :meth:`Client.connect()` like this:

>>> conn = client.connect()

We can make an HTTP request to our server using :meth:`Connection.request()`
like this, which will return a :class:`Response` namedtuple:

>>> conn.request('GET', '/', {}, None)
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

As per HTTP/1.1, multiple requests can be made using the same connection:

>>> conn.request('PUT', '/foo/bar', {}, None)
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

It's a good idea to explicitly call :meth:`Connection.close()` when you're done
using a connection, although this will likewise be done automatically when the
:class:`Connection` is garbage collected.

>>> conn.close()

For SSL (ie., TLSv1.2), you'll need to create an :class:`SSLClient` instance,
for example:

>>> from degu.client import SSLClient
>>> sslclient = SSLClient({}, ('www.wikipedia.org', 443))

When creating a :class:`SSLClient`, the first argument can be either a pre-built
`ssl.SSLContext`_, or an *sslconfig* ``dict`` that will be passed to
:func:`build_client_sslctx()`.



:class:`Client`
---------------

.. class:: Client(address, **options)

    An HTTP server to which client connections can be made.

    The *address* argument specifies the server socket address to which TCP
    connections will be made.  It can be a 2-tuple for ``AF_INIT`` or
    ``AF_INET6``, a 4-tuple for ``AF_INET``, or an ``str`` or ``bytes`` instance
    for ``AF_UNIX``.  See :ref:`client-address` for details.

    Finally, you can provide keyword-only *options* to override the defaults for
    certain client configuration values.  See :ref:`client-options` for details.

    A :class:`Client` is stateless and thread-safe.  It contains the information
    needed to create actual :class:`Connection` instances, but does not itself
    reference any socket resources.

    .. attribute:: address

        The *address* argument provided to the constructor.

        See :ref:`client-address` for details.

    .. attribute:: options

        A ``dict`` containing the client configuration options.

        This will contain the values of any keyword *options* provided to the
        constructor, and will otherwise contain the default values for the
        remaining options.

        Note that this property returns a copy of the *options* ``dict``, as
        currently modifying these options after a :class:`Client` has been
        created is not supported.

        See :ref:`client-options` for details.

    .. method:: connect()

        Create and return a new :class:`Connection` instance.



.. _client-address:

*address*
'''''''''

Both :class:`Client` and :class:`SSLClient` take an *address* argument, which
can be:

    * A ``(host, port)`` 2-tuple where the *host* is an IPv6 IP, an IPv4 IP, or
      a DNS name; the socket family will be ``AF_INET`` or ``AF_INET6`` as
      appropriate for the *host*

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple where the *host* is an
      IPv6 IP; the socket family will always be ``AF_INET6``

    * An ``str`` instance providing the filename of an ``AF_UNIX`` socket

    * A ``bytes`` instance providing the Linux abstract name of an ``AF_UNIX``
      socket

If your *address* is a 2-tuple, it's passed directly to
`socket.create_connection()`_ when creating a connection.  For example, all
three of these are valid 2-tuple *address* values::

    ('8.8.8.8', 80)
    ('2001:4860:4860::8888', 80)
    ('www.example.com', 80)

If your *address* is a 4-tuple, ``AF_INET6`` is assumed and your *address* is
passed directly to `socket.socket.connect()`_ when creating a connection,
thereby giving you access to full IPv6 semantics, including the *scopeid* needed
for `link-local addresses`_.  For example, this 4-tuple *address* would connect
to a hypothetical server listening on an IPv6 link-local address::

    ('fe80::e8b:fdff:fe75:402c', 80, 0, 3)

Finally, if your *address* is an ``str`` or ``bytes`` instance, ``AF_UNIX`` is
assumed and again your *address* is passed directly to
`socket.socket.connect()`_ when creating a connection.  For example, these are
both valid ``AF_UNIX`` *address* values::

    '/tmp/my.socket'
    b'\x0000022'



.. _client-options:

*options*
'''''''''

Both :class:`Client` and :class:`SSLClient` accept keyword-only *options* by
which you can override certain configuration defaults.

The following client *options* are supported:

    *   **base_headers** --- a ``dict`` of headers that will always be
        included in each HTTP request; some care must be taken here as these
        headers always override the same header if provided to
        :meth:`Connection.request()`; must be a ``dict``
        instance, or ``None`` to indicate no base headers; cannot include
        ``'content-length'`` or ``'transfer-encoding'`` headers; default is
        ``None``

    *   **bodies** --- a ``namedtuple`` exposing the four IO wrapper classes
        used to construct HTTP request and response bodies

    *   **timeout** --- client socket timeout in seconds; must be a positve
        ``int`` or ``float`` instance, or ``None`` to indicate no timeout

    *   **Connection** --- :meth:`Client.connect()` will return an instance of
        this class; this is a good way to provide domain-specific behavior in a
        :class:`degu.client.Connection` subclass

Unless you override any of them, the default client configuration *options*
are::

    default_client_options = {
        'base_headers': None,
        'bodies': degu.base.DEFAULT_BODIES,
        'timeout': 90,
        'Connection': degu.client.Connection,
    }

For example, you could override some of these options like this:

>>> from degu.client import Client, Connection
>>> class SuperSpecialConnection(Connection):
...     def get(uri, headers, body):
...         return self.request('GET', uri, headers, body)
... 
...     def put(uri, headers, body):
...         return self.request('PUT', uri, headers, body)
...
>>> address = ('127.0.0.1', 12345)
>>> client = Client(address,
...     base_headers={'user-agent': 'SuperSpecial/1.0'},
...     Connection=SuperSpecialConnection,
...     timeout=17,
... )

Also see the server :ref:`server-options`.



:class:`SSLClient`
------------------

.. class:: SSLClient(sslctx, address, **options)

    An HTTPS server (TLSv1.2) to which client connections can be made.

    This subclass inherits all attributes and methods from :class:`Client`.

    The *sslctx* argument must be an `ssl.SSLContext`_ appropriately configured
    for client-side TLSv1.2 use.

    Alternately, if the *sslctx* argument is a ``dict``, it's interpreted as the
    client *sslconfig* and the actual `ssl.SSLContext`_ will be implicitly built
    by calling :func:`build_client_sslctx()`.

    The *address* argument, along with any keyword *options*, are passed
    unchanged to the :class:`Client` constructor.

    An :class:`SSLClient` instance is stateless and thread-safe.  It contains
    the information needed to create actual :class:`Connection` instances, but
    does not itself reference any socket resources.

    .. attribute:: sslctx

        The *sslctx* argument provided to the constructor.

        Alternately, if *sslctx* is a ``dict``, it's interpreted as the client
        *sslconfig* and is passed to :func:`build_client_sslctx()` to build the
        actual *sslctx*.



.. _client-sslctx:

*sslctx*
''''''''



:func:`build_client_sslctx()`
-----------------------------

.. function:: build_client_sslctx(config)

    Build an `ssl.SSLContext`_ appropriately configured for client use.

    The *config* must be a ``dict`` instance, which can be empty, or can
    contain any of the following keys:

        * ``'check_hostname'`` --- whether to check that the server hostname
          matches the hostname in its SSL certificate; this value must be
          ``True`` or ``False`` and is directly used to set the
          `ssl.SSLContext.check_hostname`_ attribute; if not provided, this
          defaults to ``True``

        * ``'ca_file'`` and/or ``'ca_path'`` --- an ``str`` providing the path
          of the file or directory, respectively, containing the trusted CA
          certificates used to verify server certificates when making
          connections; if neither of these are provided, then the default
          system-wide CA certificates are used; also note that when neither of
          these of these are provided, ``'check_hostname'`` must be ``True``, as
          this is the only way to securely use the system-wide CA certificates

        * ``'cert_file'`` and ``'key_file'`` --- an ``str`` providing the path
          of the client certificate file and the client private key file,
          respectively; you can omit ``'key_file'`` if the private key is
          included in the client certificate file

    For example, typical Degu P2P usage will use a *config* something like this:

    >>> from degu.client import build_client_sslctx
    >>> config = {
    ...     'check_hostname': False,
    ...     'ca_file': '/my/server.ca',
    ...     'cert_file': '/my/client.cert',
    ...     'key_file': '/my/client.key',
    ... }
    >>> sslctx = build_client_sslctx(config)  #doctest: +SKIP

    Although you can of course directly build your own `ssl.SSLContext`_, this
    function eliminates many potential security gotchas that can occur through
    misconfiguration, and is also designed to compliment the server-side setup
    built with the :func:`degu.server.build_server_sslctx()` function.

    Opinionated security decisions this function makes:

        * The *protocol* is unconditionally set to ``ssl.PROTOCOL_TLSv1_2``

        * The *verify_mode* is unconditionally set to ``ssl.CERT_REQUIRED``, as
          there are no meaningful scenarios under which the client should not
          verify server certificates

        * The *options* unconditionally include ``ssl.OP_NO_COMPRESSION``,
          thereby preventing `CRIME-like attacks`_, and also allowing lower
          CPU usage and higher throughput on non-compressible payloads like
          media files

        * The *cipher* is unconditionally set to
          ``'ECDHE-RSA-AES256-GCM-SHA384'``, which among other things, means the
          Degu client will only connect to servers providing `perfect forward
          secrecy`_

    This function is also advantageous because the *config* is simple and easy
    to serialize/deserialize on its way to a new `multiprocessing.Process`_.
    This means that your main process doesn't need to import any unnecessary
    modules or consume any unnecessary resources.

    For unit testing and experimentation, consider using
    :class:`degu.misc.TempPKI`, for example:

    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()
    >>> sslctx = build_client_sslctx(pki.client_sslconfig)



:class:`Connection`
-------------------

.. class:: Connection(sock, host, bodies)

    Provides an HTTP client request API atop an arbitrary socket connection. 

    :meth:`Client.connect()` will return an instance of this class, but you can
    likewise directly create one yourself.  For composability, the two are
    completely decoupled.

    The *sock* argument can be a `socket.socket`_, an `ssl.SSLSocket`_, or
    anything else implementing the needed API.

    The *host* argument can be a ``str`` providing the value for the ``'host'``
    header, or it can be ``None``, in which case :meth:`Connection.request()`
    will not automatically include a ``'host'`` header in each request.

    The *bodies* argument should be a ``namedtuple`` exposing the four standard
    wrapper classes used to construct HTTP request and response bodies.

    A :class:`Connection` instance is statefull and is *not* thread-safe.

    .. attribute:: sock

        The *sock* argument passed to the constructor.

    .. attribute:: host

        The *host* argument passed to the constructor.

    .. attribute:: bodies

        The *bodies* argument passed to the constructor.

    .. attribute:: closed

        Will be ``True`` if the connection has been closed, otherwise ``False``.

    .. method:: close()

        Shutdown the underlying ``socket.socket`` instance.

        The socket is shutdown using ``socket.shutdown(socket.SHUT_RDWR)``,
        immediately preventing further reading from or writing to the socket.

        Once a connection is closed, no further requests can be made via that
        same connection instance.  To make subsequent requests, a new connection
        must be created with :meth:`Client.connect()`.

        After this method has been called, :attr:`Connection.closed` will be
        ``True``.

        Note that a connection is automatically closed when any unhandled
        exception occurs in :meth:`Connection.request()`, and is likewise
        automatically closed when the connection instance is garbage collected.

    .. method:: request(method, uri, headers, body)

        Make an HTTP request.

        The return value is a :class:`Response` namedtuple.

        The *method* must be ``'GET'``, ``'HEAD'``, ``'DELETE'``, ``'PUT'``, or
        ``'POST'``.

        The *uri* must be an ``str`` starting with ``'/'``, optionally including
        a query string.  For example, these are all valid *uri* values::

            /
            /foo
            /foo/bar?stuff=junk

        The *headers* must be a ``dict``.  All header names (keys) must be
        lowercase.

        The *body* can be:

            ==================================  ========  ================
            Type                                Encoding  Source object
            ==================================  ========  ================
            ``None``                            *n/a*     *n/a*
            ``bytes``                           Length    *n/a*
            ``bytearray``                       Length    *n/a*
            :class:`degu.base.Body`             Length    File-like object
            :class:`degu.base.BodyIter`         Length    An iterable
            :class:`degu.base.ChunkedBody`      Chunked   File-like object
            :class:`degu.base.ChunkedBodyIter`  Chunked   An iterable
            ==================================  ========  ================

        Note that the *body* must be ``None`` when the *method* is ``'GET'``,
        ``'HEAD'``, or ``'DELETE'``.

        If you want your request body to be directly uploaded from a regular
        file, simply wrap it in a :class:`degu.base.Body`.  It will be uploaded
        from the current seek position in the file up to the specified
        *content_length*.  For example, this will upload 76 bytes from the data
        slice ``[1700:1776]``:

        >>> from degu.client import Client
        >>> from degu.base import Body
        >>> client = Client(('127.0.0.1', 56789))
        >>> conn = client.connect()  #doctest: +SKIP
        >>> fp = open('/my/file', 'rb')  #doctest: +SKIP
        >>> fp.seek(1700)  #doctest: +SKIP
        >>> body = Body(fp, 76)  #doctest: +SKIP
        >>> response = conn.request('POST', '/foo', {}, body)  #doctest: +SKIP



:class:`Response`
-----------------

.. class:: Response(status, reason, headers, body)

    HTTP response nametuple returned by :meth:`Connection.request()`.

    For example, :meth:`Connection.request()` might return something like this:

    >>> from degu.client import Response
    >>> Response(200, 'OK', {}, None)
    Response(status=200, reason='OK', headers={}, body=None)

    Note that as a namedtuple, :class:`Response` doesn't do any type checking or
    argument validation itself.  The nature of the following attributes relies
    solely on the behavior of :meth:`Connection.request()`:

    .. attribute :: status

        The HTTP response status from the server.

        This will be an ``int`` such that::

            100 <= status <= 599

    .. attribute :: reason

        The HTTP response reason from the server.

        This will be an ``str`` like ``'OK'`` or ``'Not Found'``.

    .. attribute :: headers

        The HTTP response headers from the server.

        This will be a ``dict`` instance, possibly empty.  The keys will all be
        lowercase normalized using ``str.casefold()``, regardless how they were
        returned by the server.

    .. attribute :: body

        The HTTP response body from the server.

        If no response body was returned, this will be ``None``.  Otherwise,
        this will be either a :class:`degu.base.Body` or
        :class:`degu.base.ChunkedBody` instance.



.. _degu-client-v-http-client:

Degu vs. ``http.client``
------------------------

:mod:`degu.client` is similar in abstraction level to the `http.client`_ module
in the Python3 standard library, and has an API that overall should feel
familiar to those experienced with `http.client`_, although there are some key
differences.

Degu specifies the target server via the exact *address* argument used by the
underlying Python `socket`_ API.  This allows Degu to fully expose IPv6 address
semantics, including the *scopeid* needed for `link-local addresses`_, and also
allows Degu to transparently support HTTP over ``AF_UNIX``.

Consider the `HTTPConnection`_ vs the :class:`Client` constructors::

    # http.client:
    HTTPConnection(host, port=None, timeout=None, source_address=None)

    # degu.client:
    Client(address, **options)

For example, here's how to use `http.client`_ to specify the server by DNS name,
IPv4 IP, and IPv6 IP:

>>> from http.client import HTTPConnection
>>> conn = HTTPConnection('www.wikipedia.org', 80)
>>> conn = HTTPConnection('208.80.154.224', 80)
>>> conn = HTTPConnection('2620:0:861:ed1a::1', 80)

And here's the equivalent using :mod:`degu.client`:

>>> from degu.client import Client
>>> client = Client(('www.wikipedia.org', 80))
>>> client = Client(('208.80.154.224', 80))
>>> client = Client(('2620:0:861:ed1a::1', 80))  # As 2-tuple
>>> client = Client(('2620:0:861:ed1a::1', 80, 0, 0))  # As 4-tuple

But here are some :mod:`degu.client` examples that aren't possible with
`http.client`_:

>>> client = Client(('fe80::e8b:fdff:fe75:402c', 80, 0, 3))  # IPv6 link-local
>>> client = Client('/tmp/my.socket')  # AF_UNIX
>>> client = Client(b'\x0000022')  # AF_UNIX

`HTTPConnection`_ is somewhat overloaded with two distict problem domains:

    1. Information about *how* to connect to a server (the socket address, plus
       an ``ssl.SSLContext`` in the case of HTTPS)

    2. An actuall TPC connection to said server

In contrast, :mod:`degu.client` decomposes this abstraction and handles (1) via
the :class:`Client` class, and handles (2) via
:class:`Connection`.



.. _`http.client`: https://docs.python.org/3/library/http.client.html
.. _`HTTPConnection`: https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection

.. _`socket.create_connection()`: https://docs.python.org/3/library/socket.html#socket.create_connection
.. _`socket.socket.connect()`: https://docs.python.org/3/library/socket.html#socket.socket.connect
.. _`link-local addresses`: https://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`HTTP/1.1`: http://www.w3.org/Protocols/rfc2616/rfc2616.html
.. _`Apache 2.4`: https://httpd.apache.org/docs/2.4/
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`ssl.SSLContext.check_hostname`: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
.. _`CRIME-like attacks`: http://en.wikipedia.org/wiki/CRIME
.. _`perfect forward secrecy`: http://en.wikipedia.org/wiki/Forward_secrecy
.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process

.. _`socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`socket.socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`ssl.SSLSocket`: https://docs.python.org/3/library/ssl.html#ssl-sockets
