:mod:`degu.client` --- HTTP Client
==================================

.. module:: degu.client
   :synopsis: Low-level HTTP client

The :mod:`degu.client` module provides a low-level HTTP/1.1 client library.

It has an API that overall should feel familiar to those experienced with
`http.client`_ (but there are key differences, for details see
:ref:`degu-client-v-http-client`).

A :class:`Client` uses the same *address* format as the underlying Python
`socket`_ API.  For example:

>>> from degu.client import Client
>>> client = Client(('en.wikipedia.org', 80))

It specifies *where* a server is (and optional details on *how* to connect to
the server).  To make requests, use :meth:`Client.connect()` to create a
:class:`Connection`.

However, a :class:`Client` is really just for creating connections to servers
running on the localhost (possibly using HTTP over ``AF_UNIX``, which Degu
supports).

For security reasons, you should use an :class:`SSLClient` when creating
connections to any external servers:

>>> from degu.client import SSLClient
>>> sslclient = SSLClient({}, ('en.wikipedia.org', 443))

The first argument can be a pre-built `ssl.SSLContext`_, or a ``dict`` providing
the *sslconfig* for :func:`build_client_sslctx()`, the result of which will be
available via the :attr:`SSLClient.sslctx` attribute:

>>> sslclient.sslctx
<ssl.SSLContext object at 0x...>

``{}`` is shorthand for using the system-wide trusted certificate authorities
and ensuring that the hostname matches the common name (CN) in the provided
server certificate (more or less how a browser would configure SSL):

>>> import ssl
>>> sslclient.sslctx.protocol == ssl.PROTOCOL_TLSv1_2
True
>>> sslclient.sslctx.verify_mode == ssl.CERT_REQUIRED
True
>>> sslclient.sslctx.check_hostname
True

Now we'll use :meth:`Client.connect()` (which :class:`SSLClient` inherits) to
create a :class:`Connection`:

>>> conn = sslclient.connect()  #doctest: +SKIP
>>> conn.sock.cipher()  #doctest: +SKIP
('ECDHE-RSA-AES128-GCM-SHA256', 'TLSv1/SSLv3', 128)

:meth:`Connection.get()` will make a ``GET`` request, and will return a
:class:`Response` namedtuple:

>>> response = conn.get('/wiki/Portal:Science', {})  #doctest: +SKIP
>>> response.status  #doctest: +SKIP
200
>>> response.reason  #doctest: +SKIP
'OK'
>>> response.headers['transfer-encoding']  #doctest: +SKIP
'chunked'
>>> response.body  #doctest: +SKIP
ChunkedBody(<rfile>)
>>> content = response.body.read()  #doctest: +SKIP

You can make the same ``GET`` request using :meth:`Connection.request()`, which
is a generic method that can specify any supported HTTP request:

>>> response = conn.request('GET', '/wiki/Portal:Science', {}, None)  #doctest: +SKIP
>>> response.status  #doctest: +SKIP
200
>>> response.reason  #doctest: +SKIP
'OK'
>>> response.headers['transfer-encoding']  #doctest: +SKIP
'chunked'
>>> response.body  #doctest: +SKIP
ChunkedBody(<rfile>)
>>> content = response.body.read()  #doctest: +SKIP

It's a good idea to explicitly call :meth:`Connection.close()` when you're done
using a connection, although this will likewise be done automatically when a
:class:`Connection` is garbage collected.

>>> conn.close()  #doctest: +SKIP


:class:`Client`
---------------

.. class:: Client(address, **options)

    Specifies where an HTTP server is, and how to connect to it.

    >>> from degu.client import Client
    >>> client = Client(('en.wikipedia.org', 80))

    The *address* is the same used by the Python `socket`_ API.  It can be a
    2-tuple, a 4-tuple, a ``str``, or a ``bytes`` instance.  See
    :ref:`client-address` for details.

    The keyword-only *options* allow you to override certain client
    configuration defaults.  You can override *host*, *authorization*,
    *timeout*, and *on_connect*, the values of which are exposed via attributes
    of the same name:

        * :attr:`Client.host`
        * :attr:`Client.authorization`
        * :attr:`Client.timeout`
        * :attr:`Client.on_connect`

    See :ref:`client-options` for details.

    A :class:`Client` is stateless and thread-safe.  It specifies "where" the
    server is (the *address*) and "how" to connect to the server (the
    *options*), but does not itself reference any socket resources.

    To make HTTP requests, use :meth:`Client.connect()` to create a
    :class:`Connection`:

    >>> conn = client.connect()  #doctest: +SKIP
    >>> response = conn.get('/wiki/Portal:Science', {})  #doctest: +SKIP


    .. attribute:: address

        The *address* argument provided to the constructor.

        See :ref:`client-address` for details.


    .. attribute:: options

        Keyword-only *options* provided to the constructor.

        For example:

        >>> Client(('127.0.0.1', 12345), timeout=5).options
        {'timeout': 5}

        See :ref:`client-options` for details.

    .. attribute:: host

        Value of the HTTP "host" header to be included in each request.

        If the :ref:`client-address` argument provided to the constructor was
        a 2-tuple or 4-tuple, the default value will be constructed from the
        *address*:

        >>> Client(('en.wikipedia.org', 80)).host
        'en.wikipedia.org'
        >>> Client(('192.168.1.171', 5984)).host
        '192.168.1.171:5984'
        >>> Client(('fe80::e8b:fdff:fe75:402c/64', 5984, 0, 3)).host
        '[fe80::e8b:fdff:fe75:402c/64]:5984'

        If the *address* is a ``str`` or ``bytes`` instance, this attribute
        will default to ``None``:

        >>> Client('/tmp/my.socket').host is None
        True
        >>> Client(b'\x0000022').host is None
        True

        A *host* keyword option will override the default value of for this
        attribute, regardless of the *address*:

        >>> Client(('192.168.1.171', 5984), host='example.com').host
        'example.com'
        >>> Client('/tmp/my.socket', host='example.com').host
        'example.com'

        Likewise, you can use the *host* keyword option to set this attribute to
        ``None``, regardless of the *address*:

        >>> Client(('192.168.1.171', 5984), host=None).host is None
        True
        >>> Client('/tmp/my.socket', host=None).host is None
        True

        :meth:`Client.connect()` will pass :attr:`Client.host` to the
        :class:`Connection`, and when not ``None``, :meth:`Connection.request()`
        will use this value for the "host" request header.

    .. attribute:: authorization

        Value of HTTP Authorization header.

        When this value is not ``None``, it will be used as the HTTP
        Authorization header in each request made using a :class:`Connection`.

        The default is ``None``, but you can override this using the
        *authorization* keyword option.

    .. attribute:: timeout

        The client socket timeout in seconds, or ``None`` for no timeout.

        The default is ``65`` seconds, but you can override this using the
        *timeout* keyword option.

        :meth:`Client.create_socket()` sets the socket timeout to
        :attr:`Client.timeout` for all new sockets it creates.

    .. attribute:: on_connect

        Callback that is called when a new connection is created.

        If provided, this must be a callable taking a single argument, which
        must return ``True`` when the connection should be accepted.

        For example:

        >>> def my_on_connect(conn):
        ...     return True
        ...

        The *conn* argument above will be the :class:`Connection` instance
        created for the new connection.

        This callback is called after a new connection has been created, but
        before any HTTP requests have been made using that connection.  If this
        callback does not return ``True``, or if any unhandled exception occurs
        when the callback is called, the connection will be closed immediately
        and an exception will be raised.

        The default is ``None``, but you can override this using the
        *on_connect* keyword option.

    .. attribute:: base_headers

        Headers that will be unconditionally included in each request.

        This attribute will be ``None`` when no base headers have been
        specified (or implied); otherwise it will be a ``tuple`` of
        ``(name,value)`` pairs.

        :meth:`Client.connect()` will pass this attribute to the
        :class:`Connection` constructor when a new connection is created, and
        :meth:`Connection.request()` will unconditionally set these headers
        (overriding existing values if present) for each HTTP request made
        through the connection.

        :attr:`Client.host` and :attr:`Client.authorization` will be included in
        :attr:`Client.base_headers` when they have a value that isn't ``None``.

        For example, when the *address* provided to the :class:`Client`
        constructor is a 2-tuple or a 4-tuple, a default *host* value will be
        built from the *address*:

        >>> client = Client(('127.0.0.1', 12345))
        >>> client.base_headers
        (('host', '127.0.0.1:12345'),)

        You can override this by providing ``host=None`` to the :class:`Client`
        constructor:

        >>> client = Client(('127.0.0.1', 12345), host=None)
        >>> client.base_headers is None
        True

        Likewise, if you provide an *authorization* keyword option to the
        :class:`Client` constructor, it will be included:

        >>> client = Client(('127.0.0.1', 12345), authorization='foo')
        >>> client.base_headers
        (('authorization', 'foo'), ('host', '127.0.0.1:12345'))

        In addition to the *host* and *authorization* options, you can specify
        additional base headers using :meth:`Client.set_base_header`.

    .. method:: set_base_header(name, value)

        Set a base header that will be included in all requests.

        This method will add a new header to :attr:`Client.base_headers`:

        >>> client = Client(('127.0.0.1', 12345))
        >>> client.set_base_header('accept', 'application/json')
        >>> client.base_headers
        (('accept', 'application/json'), ('host', '127.0.0.1:12345'))

        This method will also replace an existing base header of the same name:

        >>> client.set_base_header('accept', '*/*')
        >>> client.base_headers
        (('accept', '*/*'), ('host', '127.0.0.1:12345'))

        Finally, you can use this method to delete an existing header of the
        same name by providing a *value* of ``None``:

        >>> client.set_base_header('accept', None)
        >>> client.base_headers
        (('host', '127.0.0.1:12345'),)

        If you use this method to delete the final remaining header value,
        :attr:`Client.base_headers` will be ``None``:

        >>> client.set_base_header('host', None)
        >>> client.base_headers is None
        True

    .. method:: create_socket()

        Create a new `socket.socket`_ connected to :attr:`Client.address`.

    .. method:: connect()

        Create a new :class:`Connection` instance.



.. _client-address:

*address*
'''''''''

Both :class:`Client` and :class:`SSLClient` take an *address* argument, which
can be:

    * A ``(host, port)`` 2-tuple where the *host* is an IPv4 IP, an IPv6 IP, or
      a DNS name

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple where the *host* is an IPv6
      IP

    * A ``str`` providing the filename of an ``AF_UNIX`` socket

    * A ``bytes`` instance providing the Linux abstract name of an ``AF_UNIX``
      socket

If your *address* is a ``(host, port)``  2-tuple, it's passed directly to
`socket.create_connection()`_ when creating a connection.  The socket family
will be ``AF_INET`` or ``AF_INET6`` as appropriate for the *host* IP (or the IP
that the DNS *host* name resolves to).

For example, all three of these are valid 2-tuple *address* values::

    ('208.80.154.224', 80)
    ('2620:0:861:ed1a::1', 80)
    ('www.wikipedia.org', 80)

If your *address* is a 4-tuple, ``AF_INET6`` is assumed, and your *address* is
passed directly to `socket.socket.connect()`_ when creating a connection,
thereby giving you access to full IPv6 semantics, including the *scopeid* needed
for `link-local addresses`_.

For example, these are both valid 4-tuple *address* values::

    ('2620:0:861:ed1a::1', 80, 0, 0)
    ('fe80::e8b:fdff:fe75:402c', 80, 0, 3)  # Link-local

Finally, if your *address* is a ``str`` or ``bytes`` instance, ``AF_UNIX`` is
assumed, and your *address* is again passed directly to
`socket.socket.connect()`_ when creating a connection.

For example, these are both valid ``AF_UNIX`` *address* values::

    '/tmp/my.socket'
    b'\x0000022'  # Linux abstract name



.. _client-options:

*options*
'''''''''

Both :class:`Client` and :class:`SSLClient` accept keyword-only *options* by
which you can override certain client configuration defaults.

The following client *options* are supported:

    *   **host** --- a ``str`` containing the value of the HTTP "host"
        request header that will be set by :meth:`Connection.request()`, or
        ``None``, in which case no "host" header will be set

    *   **authorization** --- a ``str`` containing the value of the HTTP
        "authorization" request header that will be set by
        :meth:`Connection.request()`, or ``None``, in which case no
        "authorization" header will be set

    *   **timeout** --- client socket timeout in seconds; must be a positve
        ``int`` or ``float``, or ``None`` to indicate no timeout

    *   **on_connect** --- callback called when after a new connection has been
        made, but before any HTTP requests have been made through that
        connection

Default values:

    =================  ============================  ==================================
    Option             Attribute                     Default value
    =================  ============================  ==================================
    ``host``           :attr:`Client.host`           derived from :ref:`client-address`
    ``authorization``  :attr:`Client.authorization`  ``None``
    ``timeout``        :attr:`Client.timeout`        ``65``
    ``on_connect``     :attr:`Client.on_connect`     ``None``
    =================  ============================  ==================================

Also see the server :ref:`server-options`.



:class:`SSLClient`
------------------

.. class:: SSLClient(sslctx, address, **options)

    Specifies where an HTTPS server is, and how to connect to it.

    >>> from degu.client import SSLClient
    >>> sslclient = SSLClient({}, ('en.wikipedia.org', 443))

    This subclass inherits all attributes and methods from :class:`Client`.

    The *sslctx* can be a pre-built `ssl.SSLContext`_, or a ``dict`` providing
    the *sslconfig* for :func:`build_client_sslctx()`.

    The *address*, along with any keyword-only *options*, are passed unchanged
    to the :class:`Client` constructor.

    This subclass adds the *ssl_host* option, exposed via the
    :attr:`SSLClient.ssl_host` attribute.

    An :class:`SSLClient` is stateless and thread-safe.  It specifies "where"
    the server is (the *address*) and "how" to connect to the server (the
    *sslctx* and *options*), but does not itself reference any socket resources.

    To make HTTP requests, use :meth:`Client.connect()` to create a
    :class:`Connection`:

    >>> conn = sslclient.connect()  #doctest: +SKIP
    >>> response = conn.get('/wiki/Portal:Science', {})  #doctest: +SKIP

    .. attribute:: sslctx

        The `ssl.SSLContext`_ used to wrap socket connections.

        If the *sslctx* argument provided to the contructor was a pre-built
        `ssl.SSLContext`_ instance, this attribute will contain that exact same
        instance.

        Otherwise this attribute will contain the `ssl.SSLContext`_ returned by
        :func:`build_client_sslctx()`.

    .. attribute:: ssl_host

        Value used for SNI and server certificate CN matching.

        The default value is derived from the *address* argument, but you can
        override this value using the *ssl_host* keyword option.

        If your *address* is a 2-tuple or 4-tuple, the default value will be
        the *host* portion:

        >>> SSLClient({}, ('www.wikipedia.org', 80)).ssl_host
        'www.wikipedia.org'
        >>> SSLClient({}, ('208.80.154.224', 80)).ssl_host
        '208.80.154.224'
        >>> SSLClient({}, ('2620:0:861:ed1a::1', 80, 0, 0)).ssl_host
        '2620:0:861:ed1a::1'

        Note that unlike :attr:`Client.host`, the *port* is not included.

        If your *address* is a ``str`` or a ``bytes`` instance, this value will
        default to ``None``.

        Although using SSL over ``AF_UNIX`` perhaps a bit silly, Degu does
        support this just for API completeness.

    .. method:: create_socket()

        Create a new `ssl.SSLSocket`_ connected to :attr:`Client.address`.

        This method first calls :meth:`Client.create_socket()` to create a
        `socket.socket`_, which it then wraps using
        `ssl.SSLContext.wrap_socket()`_ to produce an `ssl.SSLSocket`_.

        This method uses :attr:`SSLClient.ssl_host` for the *server_hostname*
        passed to `ssl.SSLContext.wrap_socket()`_.

        When `ssl.SSLContext.check_hostname`_ is ``True``, this is the hostname
        that will be used when matching the common name (CN) in the server
        certificate.



.. _client-sslctx:

*sslctx*
''''''''



:func:`build_client_sslctx()`
-----------------------------

.. function:: build_client_sslctx(sslconfig)

    Build an `ssl.SSLContext`_ appropriately configured for client use.
    
    This function compliments the server-side setup built with 
    :func:`degu.server.build_server_sslctx()`.

    The *sslconfig* must be a ``dict`` instance, which can be empty, or can
    contain any of the following keys:

        *   ``'check_hostname'`` --- whether to check that the server hostname
            matches the common name (CN) in its SSL certificate; this value must
            be ``True`` or ``False`` and is directly used to set the
            `ssl.SSLContext.check_hostname`_ attribute; if not provided, this
            defaults to ``True``

        *   ``'ca_file'`` and/or ``'ca_path'`` --- a ``str`` providing the path
            of the file or directory, respectively, containing the trusted CA
            certificates used to verify server certificates when making
            connections; if neither of these are provided, then the default
            system-wide CA certificates are used; also note that when neither of
            these of these are provided, ``'check_hostname'`` must be ``True``
            (if provided), as that is the only way to securely use the
            system-wide CA certificates

        *   ``'cert_file'`` and ``'key_file'`` --- a ``str`` providing the path
            of the client certificate file and the client private key file,
            respectively, by which the client can authenticate itself to the
            server

    For example, typical Degu P2P usage will use a client *sslconfig* something
    like this:

    >>> from degu.client import build_client_sslctx
    >>> sslconfig = {
    ...     'check_hostname': False,
    ...     'ca_file': '/my/server.ca',
    ...     'cert_file': '/my/client.cert',
    ...     'key_file': '/my/client.key',
    ... }
    >>> sslctx = build_client_sslctx(sslconfig)  #doctest: +SKIP

    Although you can directly build your own client-side `ssl.SSLContext`_, this
    function eliminates many potential security gotchas that can occur through
    misconfiguration.

    Opinionated security decisions this function makes:

        *   The *protocol* is unconditionally set to ``ssl.PROTOCOL_TLSv1_2``

        *   The *verify_mode* is unconditionally set to ``ssl.CERT_REQUIRED``,
            as  there are no meaningful scenarios under which the client should
            not verify server certificates

        *   The *options* unconditionally include ``ssl.OP_NO_COMPRESSION``,
            thereby preventing `CRIME-like attacks`_, and also allowing lower
            CPU usage and higher throughput on non-compressible payloads like
            media files

        *   The *ciphers* are unconditionally set to::

                'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'

            Among other things, this means the Degu client will only connect to
            servers providing `perfect forward secrecy`_

    This function is also advantageous because the *sslconfig* is simple and
    easy to serialize/deserialize on its way to a new
    `multiprocessing.Process`_.  This means that your main process doesn't need
    to import any unnecessary modules or consume any unnecessary resources when
    a :class:`degu.client.SSLClient` is only needed in a subprocess.

    For unit testing and experimentation, consider using
    a :class:`degu.misc.TempPKI` instance, for example:

    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()
    >>> sslctx = build_client_sslctx(pki.client_sslconfig)



:class:`Connection`
-------------------

.. class:: Connection(sock, base_headers)

    Provides an HTTP client request API atop an arbitrary socket connection. 

    :meth:`Client.connect()` will return an instance of this class, but you can
    likewise directly create one yourself.  For composability, the two are
    completely decoupled.

    :meth:`Connection.request()` allows any supported HTTP request to be fully
    specified via its four arguments, which is important for reverse-proxy
    applications or similar scenarios that need to be abstracted from the
    specific HTTP request method being used.

    There are also shortcuts for each of the five supported HTTP request methods:

        *   :meth:`Connection.get()`
        *   :meth:`Connection.head()`
        *   :meth:`Connection.put()`
        *   :meth:`Connection.post()`
        *   :meth:`Connection.delete()`

    And there is a shortcut for making HTTP Range requests:

        *   :meth:`Connection.get_range()`

    (For brevity, use of the shortcut methods is recommended when possible.)

    Finally, the :attr:`Connection.api` attribute exposes the standard RGI
    application API.  Under Degu, :attr:`Connection.api` will always be the
    :data:`degu.base.api` constant, which is an instance of the
    :class:`degu.base.API` namedtuple.

    A :class:`Connection` is stateful  and is *not* thread-safe.

    **Arguments**

    The *sock* argument can be a `socket.socket`_, an `ssl.SSLSocket`_, or
    anything else implementing the needed API.

    Degu currently requires *sock* to have three methods::

        sock.send(src_buf)

        sock.read_into(dst_buf)

        sock.close()

    (See the `socket.socket`_ documentation for details.)

    The *base_headers* argument must be a ``tuple`` providing headers that
    :meth:`Connection.request()` should automatically include in each request.

    Optionally, *base_headers* can be ``None``, which is treated the same as an
    empty ``tuple``.

    A ``(key, value)`` in *base_headers* will unconditionally replace the same
    should it exist in the *headers* provided to :meth:`Connection.request()`,
    which internally does something like this prior to making the request::

        def request(self, method, uri, headers, body):
            if self.base_headers:
                headers.update(self.base_headers)
            # ...

    :meth:`Client.connect()` uses the *base_headers* argument to automatically
    include an HTTP ``'host'`` header when appropriate.

    If you add your own items to *base_headers*, do so sparingly as they will be
    added to every request regardless of the HTTP method.

    Automatically modifying the request headers is generally something best done
    in application-specific wrappers.  See :ref:`high-level-client-api` for
    details.

    .. versionchanged:: 0.18

        When a :class:`Connection` closes the underlying socket connection,
        ``socket.shutdown()`` is no longer called, only ``socket.close()`` is
        called.

    .. attribute:: sock

        The *sock* argument passed to the constructor.

    .. attribute:: base_headers

        The *base_headers* argument passed to the constructor.

    .. attribute:: api

        This attribute exposes the standard RGI application API.

        Under Degu this attribute will always be the :data:`degu.base.api`
        constant, which is an instance of the :class:`degu.base.API` namedtuple.

        The long-term goal is to standardize the Degu RGI application API such
        that high-level client and server components could transparently run
        under multiple RGI compatible implementations.

        To prepare for this scenario, consumers of the Degu client API should
        create their request bodies via this attribute rather than directly
        importing :mod:`degu.base.api`, or :class:`degu.base.Body`, etc.

        .. versionchanged:: 0.16

            This attribute was renamed from ``bodies`` to ``api``.  For backward
            compatability, the ``bodies`` attribute is still present, but new
            applications should always use the ``api`` attribute instead of the
            ``bodies`` attribute as the later is deprecated and will be removed
            in some future version of Degu.

    .. attribute:: closed

        Will be ``True`` if the connection has been closed, otherwise ``False``.

    .. method:: close()

        Close the underlying ``socket.socket`` instance.

        The socket is closed using ``socket.close()``.

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

        The *method* must be ``'GET'``, ``'HEAD'``, ``'PUT'``, ``'POST'``, or
        ``'DELETE'``.

        The *uri* must be an ``str`` starting with ``'/'``, optionally including
        a query string.  For example, these are all valid *uri* values::

            /
            /foo
            /foo/bar?stuff=junk

        The *headers* must be a ``dict`` providing the request headers.  All
        header names (keys) must be lowercase.

        The *body* can be:

            ==================================  ========  ================
            Type                                Encoding  Source object
            ==================================  ========  ================
            ``None``                            *n/a*     *n/a*
            ``bytes``                           Length    *n/a*
            :class:`degu.base.Body`             Length    File-like object
            :class:`degu.base.BodyIter`         Length    An iterable
            :class:`degu.base.ChunkedBody`      Chunked   File-like object
            :class:`degu.base.ChunkedBodyIter`  Chunked   An iterable
            ==================================  ========  ================

        Note that the *body* must be ``None`` when the *method* is ``'GET'``,
        ``'HEAD'``, or ``'DELETE'``.

        If you want your request body to be directly uploaded from a regular
        file, simply wrap it in a :class:`degu.base.Body` via the
        :attr:`Connection.api` attribute.

        The file will be uploaded from its current seek position up to the
        specified *content_length*.  For example, this will upload 76 bytes from
        the from the slice ``[1700:1776]``:

        >>> fp = open('/my/file', 'rb')  #doctest: +SKIP
        >>> fp.seek(1700)  #doctest: +SKIP
        >>> body = conn.api.Body(fp, 76)  #doctest: +SKIP
        >>> response = conn.request('POST', '/foo', {}, body)  #doctest: +SKIP

    .. method:: get(uri, headers)

        Shortcut for making a ``GET`` request.

        This calls :meth:`Connection.request()` with a *method* of ``'GET'``
        and a *body* of ``None``.

        These two are equivalent:

        >>> response = conn.get(uri, headers)  #doctest: +SKIP
        >>> response = conn.request('GET', uri, headers, None)  #doctest: +SKIP

    .. method:: get_range(uri, headers, start, stop)

        Shortcut for making a ``GET`` requests with a ``'range'`` header.

        The *start* and *stop* arguments must both be an ``int`` such that::

            0 <= start < stop

        This method will add a ``'range'`` header to the provided *headers*, and
        will then call :meth:`Connection.request()` with a *method* of
        ``'GET'`` and a *body* of ``None``.

        The value of the ``'range'`` header will be a :class:`degu.base.Range`
        created using the provided *start* and *stop* arguments.

        This:

        >>> response = conn.get_range(uri, headers, start, stop)  #doctest: +SKIP

        Is equivalent to this:
    
        >>> from degu.base import Range
        >>> headers['range'] = Range(start, stop)  #doctest: +SKIP
        >>> response = conn.request('GET', uri, headers, None)  #doctest: +SKIP

        (See :ref:`eg-range-requests` in the tutorial.)

    .. method:: head(uri, headers)

        Shortcut for making a ``HEAD`` request.

        This calls :meth:`Connection.request()` with a *method* of ``'HEAD'``
        and a *body* of ``None``.

        These two are equivalent:

        >>> response = conn.head(uri, headers)  #doctest: +SKIP
        >>> response = conn.request('HEAD', uri, headers, None)  #doctest: +SKIP

    .. method:: put(uri, headers, body)

        Shortcut for making a ``PUT`` request.

        This calls :meth:`Connection.request()` with a *method* of ``'PUT'``

        These two are equivalent:

        >>> response = conn.put(uri, headers, body)  #doctest: +SKIP
        >>> response = conn.request('PUT', uri, headers, body)  #doctest: +SKIP

    .. method:: post(uri, headers, body)

        Shortcut for making a ``POST`` request.

        This calls :meth:`Connection.request()` with a *method* of ``'POST'``

        These two are equivalent:

        >>> response = conn.post(uri, headers, body)  #doctest: +SKIP
        >>> response = conn.request('POST', uri, headers, body)  #doctest: +SKIP

    .. method:: delete(uri, headers)

        Shortcut for making a ``DELETE`` request.

        This calls :meth:`Connection.request()` with a *method* of ``'DELETE'``
        and a *body* of ``None``.

        These two are equivalent:

        >>> response = conn.delete(uri, headers)  #doctest: +SKIP
        >>> response = conn.request('DELETE', uri, headers, None)  #doctest: +SKIP



:class:`Response`
-----------------

.. class:: Response(status, reason, headers, body)

    HTTP response nametuple returned by :meth:`Connection.request()`.

    For example, :meth:`Connection.request()` might return something like this:

    >>> from degu.client import Response
    >>> Response(200, 'OK', {}, None)
    Response(status=200, reason='OK', headers={}, body=None)

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



.. _high-level-client-API:

High-level client APIs
----------------------

:mod:`degu.client` aims to be as high-level as possible while still being
completely generic.  As such, the Degu client API is quite low-level.

Rather than trying to build a *moderately* high-level API (at the expense of
being truly universal), the preferred Degu pattern is:

    1.  Use the low-level, generic Degu client API whenever reasonable

    2.  Otherwise use Degu as a building block for *extremely* high-level,
        domain-specific wrappers that exactly capture a specific pattern without
        having to make any compromises for the sake of generality

An application might use a number of these high-level, domain-specific wrappers,
each to capture one of a number of specialized use-cases.

The recommended way to implement such a high-level wrapper is modeled after the
`io`_ module in the Python standard library.

The Degu equivalent of the *Raw I/O* layer in the `io`_ module is provided by
the "raw" client classes (:class:`Client` and :class:`SSLClient`), plus the
"raw" connection class (:class:`Connection`).

It's best to implement your high-level, domain-specific API as a pair of classes
that wrap these raw objects.  Such wrappers are the Degu equivalent of the
high-level *Text I/O* and *Binary I/O* layers in the `io`_ module.

Your client wrapper should take the raw client object as its first argument, and
should implement an equivalent to :meth:`Client.connect()`:

>>> class ClientWrapper:
...     def __init__(self, client):
...         self.client = client
... 
...     def connect(self):
...         conn = self.client.connect()
...         return ConnectionWrapper(conn)
...

(Note that such a wrapper is nicely abstracted from how its *client* argument
was constructed.  The *client* could be a :class:`Client`, an
:class:`SSLClient`, or any other object providing the needed API.)

Your connection wrapper should take the raw connection object as its first
argument, and should implement an equivalent to :attr:`Connection.closed` and
:meth:`Connection.close()`:

>>> class ConnectionWrapper:
...     def __init__(self, conn):
...         self.conn = conn
... 
...     @property
...     def closed(self):
...         return self.conn.closed
... 
...     def close(self):
...         return self.conn.close()
... 
...     def request(method, uri, headers, body):
...         response = self.conn.request(method, uri, headers, body)
...         if not (200 <= response.status <= 299):
...             raise Exception(
...                 '{:d} {}'.format(response.status, response.reason)
...             )
...         return response
... 

The ``ConnectionWrapper.request()`` method above demonstrates a feature that can
be extremely useful for the end-point client consumer: automatically raising an
exception when the request didn't return a ``2xx`` HTTP response status.

But it likewise demonstrates why even this seemingly innocent high-level
behavior is inappropriate for the generic Degu client API.  When implementing a
reverse-proxy, a central focus for Degu, you typically want to relay the
upstream HTTP response without transformation or interpretation.



.. _degu-client-v-http-client:

Degu vs. ``http.client``
------------------------

:mod:`degu.client` is heavily inspired by the `http.client`_ module in the
Python standard library.

Here's a summary of how :mod:`degu.client` differs from `http.client`_, and some
rationale for why Degu took a different approach in each case.

**Specifying "where" the server is**

Degu specifies the target server via the exact *address* argument used by the
underlying Python `socket`_ API.  This allows Degu to fully expose IPv6 address
semantics, including the *scopeid* needed for `link-local addresses`_, and also
allows Degu to transparently support HTTP over ``AF_UNIX``.

Consider the `HTTPConnection`_ vs. :class:`Client` constructors::

    # http.client:
    HTTPConnection(host, port=None, timeout=None, source_address=None)

    # degu.client:
    Client(address, **options)

For example, here's how to use `http.client`_ to specify the server by DNS name,
IPv4 IP, and IPv6 IP:

>>> from http.client import HTTPConnection
>>> client = HTTPConnection('www.wikipedia.org', 80)
>>> client = HTTPConnection('208.80.154.224', 80)
>>> client = HTTPConnection('2620:0:861:ed1a::1', 80)

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

(Read about the Client :ref:`client-address` argument for more details.)

**Specifying "how" to connect to the server**

Again, consider the `HTTPConnection`_ vs. :class:`Client` constructors::

    # http.client:
    HTTPConnection(host, port=None, timeout=None, source_address=None)

    # degu.client:
    Client(address, **options)


**Connections**

`HTTPConnection`_ is rather overloaded because it is really *two* types of
objects (from two different problem domains) entangled into one:

    1.  A server specification object ("where" the server is and "how" to create
        connections to it)

    2.  A connection object (a specific TCP connection created according to the
        "where" and "how")

An `HTTPConnection`_ instance itself acts as the connection object for the
current TCP connection (when there is one).  Although you can create, use, and
close any number of TCP connections sequentially, one after the other, you
cannot create multiple, *concurrent* TCP connections without creating multiple,
concurrent `HTTPConnection`_ instances.

For example:

>>> client = HTTPConnection('en.wikipedia.org', 80)
>>> # 1st connection:
>>> client.connect()  #doctest: +SKIP
>>> client.request('GET', '/wiki/Main_Page', None, {})  #doctest: +SKIP
>>> response = client.getresponse()  #doctest: +SKIP
>>> page1 = response.read()  #doctest: +SKIP
>>> client.close()  #doctest: +SKIP
>>> # 2nd connection:
>>> client.connect()  #doctest: +SKIP
>>> client.request('GET', '/wiki/Portal:Science', None, {})  #doctest: +SKIP
>>> response = client.getresponse()  #doctest: +SKIP
>>> page2 = response.read()  #doctest: +SKIP
>>> client.close()  #doctest: +SKIP

(And the same goes for `HTTPSConnection`_.)

In contrast, Degu decouples this and uses an independent type of object for
each problem domain:

    1. Server specification object --- :class:`Client` or :class:`SSLClient`

    2. Connection object --- :class:`Connection`

Degu allows you to create an arbitrary number of concurrent connection objects
from the same server specification object.

For example:

>>> client = Client(('en.wikipedia.org', 80))
>>> # Two concurrent connections:
>>> conn1 = client.connect()  #doctest: +SKIP
>>> conn2 = client.connect()  #doctest: +SKIP
>>> response1 = conn1.request('GET', '/wiki/Main_Page', {}, None)  #doctest: +SKIP
>>> response2 = conn2.request('GET', '/wiki/Portal:Science', {}, None)  #doctest: +SKIP
>>> page1 = response1.body.read()  #doctest: +SKIP
>>> page2 = response2.body.read()  #doctest: +SKIP
>>> conn1.close()  #doctest: +SKIP
>>> conn2.close()  #doctest: +SKIP



.. _`http.client`: https://docs.python.org/3/library/http.client.html
.. _`HTTPConnection`: https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection
.. _`HTTPSConnection`: https://docs.python.org/3/library/http.client.html#http.client.HTTPSConnection

.. _`socket.create_connection()`: https://docs.python.org/3/library/socket.html#socket.create_connection
.. _`socket.socket.connect()`: https://docs.python.org/3/library/socket.html#socket.socket.connect
.. _`link-local addresses`: https://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`HTTP/1.1`: https://www.w3.org/Protocols/rfc2616/rfc2616.html
.. _`Apache 2.4`: https://httpd.apache.org/docs/2.4/
.. _`CRIME-like attacks`: https://en.wikipedia.org/wiki/CRIME
.. _`perfect forward secrecy`: https://en.wikipedia.org/wiki/Forward_secrecy
.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process

.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`ssl.SSLContext.check_hostname`: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
.. _`ssl.SSLContext.wrap_socket()`: https://docs.python.org/3/library/ssl.html#ssl.SSLContext.wrap_socket

.. _`socket`: https://docs.python.org/3/library/socket.html
.. _`socket.socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`ssl.SSLSocket`: https://docs.python.org/3/library/ssl.html#ssl-sockets

.. _`io`: https://docs.python.org/3/library/io.html

