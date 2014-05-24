:mod:`degu.client` --- HTTP Client
==================================

.. module:: degu.client
   :synopsis: Low-level HTTP client

The :mod:`degu.client` module provides a low-level HTTP/1.1 client library.

:mod:`degu.client` is similar in abstraction level to the `http.client`_ module
in the Python3 standard library, and has an API that overall should feel
familiar to those experienced with `http.client`_ (although there are some major
differences).

For example, say we define a simple RGI application and create a
:class:`degu.misc.TempServer` instance:

>>> def example_app(request):
...     return (200, 'OK', {'x-msg': 'hello, world'}, None)
...
>>> from degu.misc import TempServer
>>> server = TempServer(('127.0.0.1', 0), None, example_app)


We can then create a :class:`Client` instance like this:

>>> from degu.client import Client
>>> client = Client(server.address)

And then create a :class:`Connection` using :meth:`Client.connect()` like this:

>>> conn = client.connect()

And finally make a request to our server using :meth:`Connection.request()` like
this, which will return a :class:`Response` namedtuple:

>>> conn.request('GET', '/')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

Multiple requests can be made using the same connection:

>>> conn.request('PUT', '/foo/bar')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

In some circumstances you might want to explicitly close a connection using
:meth:`Connection.close()`, although this will likewise be done automatically
when the connection instance is garbage collected:

>>> conn.close()

For SSL (specifically, for TLS 1.2), you'll need an :class:`SSLClient` instance.

Also, see the :func:`create_client()` and :func:`create_sslclient()`
convenience functions, especially when connecting to Apache servers.



Connection *address*
--------------------

Both :class:`Client` and :class:`SSLClient` take an *address* argument, which
can be:

    * A ``(host, port)`` 2-tuple where the *host* is an IPv4 IP, an IPv6 IP, or
      a DNS name

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple where the *host* is an
      IPv6 IP

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



HTTP 'host' header
------------------

Considering the highly specialized P2P use case that Degu is aimed at, sending
an HTTP ``'host'`` header along with *every* request isn't particularly
meaningful.

For one, the Degu server itself doesn't support named-based virtual hosts, and
will typically be reached via an IP address alone, not via a DNS name.  For
another, Degu supports HTTP over ``AF_UNIX``, a scenario where the HTTP
``'host'`` header tends to be *extra* meaningless.

A strait-forward way to minimize the overhead of the HTTP protocol is to simply
send fewer headers along with each request and response, and the Degu client
aggressively pursues this optimization path.  By default, :class:`Client` and
:class:`SSLClient` don't include *any* extra headers in their requests that
weren't provided to :meth:`Connection.request()`.

Of particular note, the Degu client doesn't by default include an HTTP
``{'connection': 'keep-alive'}`` header, which is only needed for backward
compatibly with HTTP/1.0 servers (in HTTP/1.1, connection-reuse is assumed).
Likewise, the Degu client doesn't by default include an HTTP ``'user-agent'``
header.

If you need to include specific HTTP headers in every request, just provide them
in the *base_headers* when creating a :class:`Client` or an :class:`SSLClient`
instance.

However, note that when the Degu client does *not* include an HTTP ``'host'``
header with every request, it's not operating in a strictly `HTTP/1.1`_
compliant fashion, and that this is incompatible with at least one of the HTTP
servers that the Degu client aims to support (`Apache 2.4`_).

When making requests to Apache, or to other servers with similar requirements,
consider using the :func:`create_client()` or :func:`create_sslclient()`
convenience function, which will automatically add an appropriate ``'host'``
header in the *base_headers* for the resulting :class:`Client` or
:class:`SSLClient`, respectively.



Helper functions
----------------

.. function:: create_client(url, base_headers=None)

    Convenience function to create a :class:`Client` from a *url*.

    For example:

    >>> from degu.client import create_client
    >>> client = create_client('http://example.com')
    >>> client.address
    ('example.com', 80)
    >>> client.base_headers
    {'host': 'example.com'}

    Unlike when directly creating a :class:`Client` instance, this function will
    automatically include an appropriate ``'host'`` header in *base_headers*.
    Note that this is needed for compatibility with Apache, even when connecting
    to Apache via an IP address alone.

    A ``ValueError`` will be raise if the *url* scheme isn't ``'http'``.

    If the *url* doesn't include a port, the port will default to ``80``.


.. function:: create_sslclient(sslctx, url, base_headers=None)

    Convenience function to create an :class:`SSLClient` from a *url*.

    For example:

    >>> from degu.client import create_sslclient, build_client_sslctx
    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()
    >>> sslctx = build_client_sslctx(pki.get_client_config())
    >>> sslclient = create_sslclient(sslctx, 'https://example.com')
    >>> sslclient.address
    ('example.com', 443)
    >>> sslclient.base_headers
    {'host': 'example.com'}

    Unlike when directly creating an :class:`SSLClient` instance, this function
    will automatically include an appropriate ``'host'`` header in
    *base_headers*.  Note that this is needed for compatibility with Apache,
    even when connecting to Apache via an IP address alone.

    A ``ValueError`` will be raise if the *url* scheme isn't ``'https'``.

    If the *url* doesn't include a port, the port will default to ``443``.

    Also see :func:`build_client_sslctx()` and :class:`degu.misc.TempPKI`.


.. function:: build_client_sslctx(config)

    Build an `ssl.SSLContext`_ appropriately configured for client use.

    The *config* must be a ``dict`` instance, which can be empty, or can
    contain any of the following keys:

        * ``'check_hostname'`` - whether to check that the server hostname
          matches the hostname in its SSL certificate; this value must be
          ``True`` or ``False`` and is directly used to set the
          `ssl.SSLContext.check_hostname`_ attribute; if not provided, this
          defaults to ``True``

        * ``'ca_file'`` and/or ``'ca_path'`` - an ``str`` providing the path of
          the file or directory, respectively, containing the trusted CA
          certificates use to verify server certificates when making
          connections; if neither of these are provided, then the default
          system-wide CA certificates are used; also note that when neither of
          these of these are provided, ``'check_hostname'`` must be ``True``, as
          this is the only way to securely use the system-wide CA certificates

        * ``'cert_file'`` and ``'key_file'`` - an ``str`` providing the path of
          the client certificate file and the client private key file,
          respectively; you can omit ``'key_file'`` if the private key is
          included in the client certificate file

    For example, typical Degu P2P use will use a *config* something like this:

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
    >>> sslctx = build_client_sslctx(pki.get_client_config())



:class:`Client` class
---------------------

.. class:: Client(address, base_headers=None)

    Represents an HTTP server to which Degu can make client connections.

    The *address* must be a 2-tuple, a 4-tuple, an ``str``, or ``bytes``.

    The *base_headers*, if provided, must be a ``dict``.  All header names
    (keys) must be lowercase as produced by ``str.casefold()``, and
    *base_headers* cannot include a ``'content-length'`` or a
    ``'transfer-encoding'``.

    Note that headers in *base_headers* will unconditionally override the same
    headers should they be passed to :meth:`Connection.request()`.

    A :class:`Client` instance is stateless and thread-safe.  It contains the
    information needed to create actual :class:`Connection` instances, but does
    not itself reference any socket resources.

    .. attribute:: address

        The *address* passed to the constructor.

    .. attribute:: base_headers

        The *base_headers* passed to the constructor.

    .. method:: connect()

        Create a new :class:`Connection` instance.



:class:`SSLClient` subclass
---------------------------

.. class:: SSLClient(sslctx, address, base_headers=None)

    Represents an HTTPS server to which Degu can make client connections.

    This subclass inherits all attributes and methods from :class:`Client`.

    The *sslctx* must be an ``ssl.SSLContext`` instance configured for
    ``ssl.PROTOCOL_TLSv1_2``.  It's best to build *sslctx* using
    :func:`build_client_sslctx()`.

    The *address* and *base_headers* arguments are passed unchanged to the
    :class:`Client` constructor.

    An :class:`SSLClient` instance is stateless and thread-safe.  It contains
    the information needed to create actual :class:`Connection` instances, but
    does not itself reference any socket resources.

    .. attribute:: sslctx

        The *sslctx* passed to the constructor.



:class:`Connection` class
-------------------------

.. class:: Connection(sock, base_headers)

    Represents a specific connection to an HTTP (or HTTPS) server.

    Note that connections are created using :meth:`Client.connect()` rather than
    by directly creating an instance of this class.

    The *sock* will be either a ``socket.socket`` or an ``ssl.SSLSocket``.

    The *base_headers* will be the same *base_headers* passed to the
    :class:`Client` constructor.

    Note that headers in *base_headers* will unconditionally override the same
    headers should they be passed to :meth:`Connection.request()`.

    A :class:`Connection` instance is statefull and is *not* thread-safe.

    .. attribute :: sock

        The *sock* passed to the constructor.

    .. attribute :: base_headers

        The *base_headers* passed to the constructor.

    .. attribute :: closed

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

    .. method:: request(method, uri, headers=None, body=None)

        Make an HTTP request.

        The *method* must be ``'GET'``, ``'PUT'``, ``'POST'``, ``'DELETE'``, or
        ``'HEAD'``.

        The *uri* must be an ``str`` starting with ``'/'``, optionally including
        a query string.  For example, these are all valid *uri* values::

            /
            /foo/bar
            /foo/bar?stuff=junk

        The *headers*, if provided, must be a ``dict``.  All header names (keys)
        must be lowercase as produced by ``str.casefold()``.

        The *body*, if provided, must be a ``bytes``, ``bytearray``, or
        ``io.BufferedReader`` instance, or an instance of one of the three
        :mod:`degu.base` output wrapper classes:

            * :class:`degu.base.Output`
            * :class:`degu.base.ChunkedOutput`
            * :class:`degu.base.FileOutput`

        The return value is a :class:`Response` namedtuple.



:class:`Response` namedtuple
----------------------------

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
        this will be either a :class:`degu.base.Input` or
        :class:`degu.base.ChunkedInput` instance.


.. _`http.client`: https://docs.python.org/3/library/http.client.html
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

