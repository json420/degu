:mod:`degu.server` --- HTTP Server
==================================

.. module:: degu.server
   :synopsis: Embedded HTTP Server


As a quick example, say you have this :doc:`rgi` application:

>>> def my_app(session, request, bodies):
...     if request.method not in {'GET', 'HEAD'}:
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'hello, world'
...     headers = {'content-length': len(body), 'content-type': 'text/plain'}
...     if request.method == 'GET':
...         return (200, 'OK', headers, body)
...     return (200, 'OK', headers, None)  # No response body for HEAD

(For a short primer on implementing RGI server applications, please read about
the server :ref:`server-app` argument.)

You can create a :class:`Server` like this:

>>> from degu.server import Server
>>> server = Server(('::1', 0, 0, 0), my_app)

And then start the server by calling :meth:`Server.serve_forever()`.

However, note that :meth:`Server.serve_forever()` will block the calling thread
forever.  When embedding Degu within another application, it's generally best to
run your server in its own `multiprocessing.Process`_,  which you can easily
do by creating a :class:`degu.EmbeddedServer`:

>>> from degu import EmbeddedServer
>>> def my_build_func():
...     return my_app
...
>>> server = EmbeddedServer(('::1', 0, 0, 0), my_build_func)

You can create a suitable :class:`degu.client.Client` using the
:attr:`degu.EmbeddedServer.address`:

>>> from degu.client import Client
>>> client = Client(server.address)
>>> conn = client.connect()
>>> response = conn.request('GET', '/', {}, None)
>>> response.body.read()
b'hello, world'

Running your Degu server in its own process has many advantages.  It means there
will be no thread contention between the Degu server process and your main
application process, and it also means you can forcibly and instantly kill the
server process whenever you need (something you can't do with a thread).  For
example, to kill the server process we just created:

>>> server.terminate()



:class:`Server`
---------------

.. class:: Server(address, app, **options)

    An HTTP server instance.

    >>> def my_app(session, request, bodies):
    ...     return (200, 'OK', {}, b'hello, world')
    ...
    >>> from degu.server import Server
    >>> server = Server(('127.0.0.1', 0), my_app)

    The *address* is the same used by the Python `socket`_ API.  It can be a
    2-tuple, a 4-tuple, a ``str``, or a ``bytes`` instance.  See
    :ref:`server-address` for details.

    The *app* is your :doc:`rgi` server application.  It must be a callable
    object (called to handle each HTTP request), and can optionally have a
    callable ``app.on_connect()`` attribute (called to handle each TCP
    connection).  See :ref:`server-app` for details.

    The keyword-only *options* allow you to override certain server
    configuration defaults.  You can override *max_connections*, *max_requests*,
    *timeout*, and *bodies*, and their values are exposed via attributes of the
    same name:

        * :attr:`Server.max_connections`
        * :attr:`Server.max_requests`
        * :attr:`Server.timeout`
        * :attr:`Server.bodies`

    See :ref:`server-options` for details.

    .. attribute:: address

        The bound server address as returned by `socket.socket.getsockname()`_.

        Note that this wont necessarily match the *address* argument provided to
        the constructor.  As Degu is designed for per-user server instances
        running on dynamic ports, you typically specify port ``0`` in a 2-tuple
        or 4-tuple *address* argument, for example::

            ('127.0.0.1', 0)  # AF_INET (IPv4)
            ('::1', 0, 0, 0)  # AF_INET6 (IPv6)

        In which case :attr:`Server.address` will contain the port assigned by
        the kernel.  For example, assuming port ``12345`` was assigned::

            ('127.0.0.1', 12345)  # AF_INET (IPv4)
            ('::1', 12345, 0, 0)  # AF_INET6 (IPv6)

        See :ref:`server-address` for details.

    .. attribute:: app

        The *app* argument provided to the constructor.

        See :ref:`server-app` for details.

    .. attribute:: options

        Keyword-only *options* provided to the constructor.
        
        See :ref:`server-options` for details.

    .. attribute:: max_connections

        Max concurrent TCP connections allowed by server.

        Default is ``25``; can be overridden via the *max_connections* keyword
        option.

        When this limit is reached, subsequent connection attempts will be
        rejected till the handling of at least one of the existing connections
        has completed.

    .. attribute:: max_requests

        Max HTTP requests allowed through a single TCP connection.

        Default is ``500``; can be overridden via the *max_requests* keyword
        option.

        When this limit is reached for a specific TCP connection, the connection
        will be unconditionally shutdown.

    .. attribute:: timeout

        Socket timeout in seconds.

        Default is ``30`` seconds; can be overridden via the *timeout* keyword
        option.

        Among other things, this timeout controls how long the server will keep
        a TCP connection open while waiting for the client to make an additional
        HTTP request.  

    .. attribute:: bodies

        A namedtuple exposing the IO abstraction API.

        Default is :attr:`degu.base.bodies`; can be overridden via the *bodies*
        keyword option.

    .. method:: serve_forever()

        Start the server in multi-threaded mode.

        The caller will block forever.



.. _server-address:

*address*
'''''''''

Both :class:`Server` and :class:`SSLServer` take an *address* argument, which
can be:

    * A ``(host, port)`` 2-tuple for ``AF_INET``, where the *host* is an IPv4 IP

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple for ``AF_INET6``, where the
      *host* is an IPv6 IP

    * An ``str`` providing the filename of an ``AF_UNIX`` socket

    * A ``bytes`` instance providing the Linux abstract name of an ``AF_UNIX``
      socket (typically an empty ``b''`` so that the abstract name is assigned
      by the kernel)

In all cases, your *address* argument is passed directly to
`socket.socket.bind()`_.  Among other things, this gives you access to full
IPv6 address semantics when using an ``AF_INET6`` 4-tuple, including the
*scopeid* needed for `link-local addresses`_.

Typically you'll run your ``AF_INET`` or ``AF_INET6`` Degu server on a random,
unprivileged port, so if your *address* is a 4-tuple or 2-tuple, you'll
typically supply ``0`` for the *port*, in which case a port will be assigned by
the kernel.

However, after you create your :class:`Server` or :class:`SSLServer`, you'll
need to know what port was assigned (for example, so you can advertise this port
to peers on the local network).

:attr:`Server.address` will contain the value returned by
`socket.socket.getsockname()`_ for the socket upon which your server is
listening.

For example, assuming port ``54321`` was assigned, :attr:`Server.address` would
be something like this for ``AF_INET`` (IPv4)::

    ('127.0.0.1', 54321)

Or something like this for ``AF_INET6`` (IPv6)::

    ('::1', 54321, 0, 0)

Likewise, you'll typically bind your ``AF_INET`` or ``AF_INET6`` Degu server to
either the special loopback-IP or the special any-IP addresses.

For example, these are the two most common ``AF_INET`` 2-tuple *address*
values, for the loopback-IP and the any-IP, respectively::

    ('127.0.0.1', 0)
    ('0.0.0.0', 0)

And these are the two most common ``AF_INET6`` 4-tuple *address* values, for the
loopback-IP and the any-IP, respectively::

    ('::1', 0, 0, 0)
    ('::', 0, 0, 0)

.. note::

    Although Python's `socket.socket.bind()`_ will accept a 2-tuple for an
    ``AF_INET6`` family socket, the Degu server does not allow this.  An IPv6
    *address* must always be a 4-tuple.  This restriction gives Degu a simple,
    unambiguous way of selecting between the ``AF_INET6`` and ``AF_INET``
    families, without needing to inspect ``address[0]`` (the host portion).

On the other hand, if your ``AF_UNIX`` *address* is an ``str`` instance, it must
be the absolute, normalized filename of a socket file that does *not* yet exist.
For example, this is a valid ``str`` *address* value::

    '/tmp/my/server.socket'

To avoid race conditions, you should strongly consider using a random, temporary
filename for your socket.

Finally, if your ``AF_UNIX`` *address* is a ``bytes`` instance, you should
typically provide an empty ``b''``, in which cases the Linux abstract socket
name will be assigned by the kernel.  For example, if you provide this *address*
value::

    b''

:attr:`Server.address` will contain the assigned abstract socket name, something
like::

    b'\x0000022'



.. _server-app:

*app*
'''''

Both :class:`Server` and :class:`SSLServer` take an *app* argument, by which you
provide your HTTP request handler, and can optionally provide a TCP connection
handler.

Here's a quick primer on implementing Degu server applications, but for full
details, please see the :doc:`rgi` (RGI) specification.


**HTTP request handler:**

Your *app* must be a callable object that accepts three arguments, for example:

>>> def my_app(session, request, bodies):
...     return (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')
...

The *session* argument will be a ``dict`` instance something like this::

    session = {
        'client': ('127.0.0.1', 12345),
    }

The *request* argument will be a ``dict`` instance something like this::

    request = {
        'method': 'GET',
        'uri': '/foo/bar/baz?stuff=junk',
        'script': ['foo'],
        'path': ['bar', 'baz'],
        'query': 'stuff=junk',
        'headers': {'accept': 'text/plain'},
        'body': None,
    }

Finally, the *bodies* argument will be a ``namedtuple`` exposing four wrapper
classes that can be used to specify the HTTP response body:

==========================  ==================================
Exposed via                 Degu implementation
==========================  ==================================
``bodies.Body``             :class:`degu.base.Body`
``bodies.BodyIter``         :class:`degu.base.BodyIter`
``bodies.ChunkedBody``      :class:`degu.base.ChunkedBody`
``bodies.ChunkedBodyIter``  :class:`degu.base.ChunkedBodyIter`
==========================  ==================================

Your ``app()`` must return a 4-tuple containing the HTTP response::

    (status, reason, headers, body)

Which in the case of our example was::

    (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')


**TCP connection handler:**

If your *app* argument itself has a callable ``on_connect`` attribute, it must
accept two arguments, for example:

>>> class MyApp:
...     def __call__(self, session, request, bodies):
...         return (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')
... 
...     def on_connect(self, session, sock):
...         return True
...

The *session* argument will be same ``dict`` instance passed to your
``app()`` HTTP request handler, something like this::

    session = {
        'client': ('127.0.0.1', 12345),
    }

Finally, the *sock* argument will be a `socket.socket`_ when running your app in
a :class:`Server`, or an `ssl.SSLSocket`_ when running your app in an
:class:`SSLServer`.

Your ``app.on_connect()`` will be called after a new TCP connection has been
accepted, but before any HTTP requests have been handled via that TCP
connection.

It must return ``True`` when the connection should be accepted, or return
``False`` when the connection should be rejected.

If your *app* has an ``on_connect`` attribute that is *not* callable, it must be
``None``.  This allows you to disable the ``app.on_connect()`` handler in a
subclass, for example:

>>> class MyAppSubclass(MyApp):
...     on_connect = None
...


**Persistent per-connection session:**

The exact same *session* instance will be used for all HTTP requests made
through a specific TCP connection.

This means that your ``app()`` HTTP request handler can use the *session*
argument to store, for example, per-connection resources that will likely be
used again when handling subsequent HTTP requests made through that same TCP
connection.

Likewise, this means that your optional ``app.on_connect()`` TCP connection
handler can use the *session* argument to store, for example,
application-specific per-connection authentication information.

If your ``app()`` HTTP request handler adds anything to the *session*, it should
prefix the key with ``'__'`` (double underscore).  For example:

>>> def my_app(session, request, bodies):
...     body = session.get('__body')
...     if body is None:
...         body = b'hello, world'
...         session['__body'] = body
...     return (200, 'OK', {'content-type': 'text/plain'}, body)
...

Likewise, if your ``app.on_connect()`` TCP connection handler adds anything to
the *session*, it should prefix the key with ``'_'`` (underscore).  For example:

>>> class MyApp:
...     def __call__(self, session, request, bodies):
...         if session.get('_user') != 'admin':
...             return (403, 'Forbidden', {}, None)
...         return (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')
...
...     def on_connect(self, sock, session):
...         # Somehow authenticate the user who made the connection:
...         session['_user'] = 'admin'
...         return True
...



.. _server-options:

*options*
'''''''''

Both :class:`Server` and :class:`SSLServer` accept keyword *options* by which
you can override certain configuration defaults.

The following server configuration *options* are supported:

    *   **max_connections** --- max number of concurrent TCP connections the
        server will allow; once this limit has been reached, subsequent
        connections will be rejected till one or more existing connections are
        closed; a lower value will reduce the peak potential memory usage; must
        be a positive ``int``

    *   **max_requests** --- max number of HTTP requests that can be handled
        through a single TCP connection before that connection is forcibly
        closed by the server; a lower value will minimize the impact of heap
        fragmentation and will tend to keep the memory usage flatter over time;
        a higher value can provide better throughput when a large number of
        small requests and responses need to travel in quick succession through
        the same TCP connection (typical for CouchDB-style structured data
        sync); it must be a positive ``int``

    *   **timeout** --- server socket timeout in seconds; must be a positve
        ``int`` or ``float`` instance

    *   **bodies** --- a namedtuple exposing the four IO wrapper classes used to
        construct HTTP request and response bodies;
        see :class:`degu.base.BodiesAPI`
        

The default values of which are:

    ==============================  ========================
    Option/Attribute                Default
    ==============================  ========================
    :attr:`Server.max_connections`  ``25``
    :attr:`Server.max_requests`     ``500``
    :attr:`Server.timeout`          ``30``
    :attr:`Server.bodies`           :attr:`degu.base.bodies`
    ==============================  ========================



:class:`SSLServer`
------------------

.. class:: SSLServer(sslctx, address, app, **options)

    An HTTPS server instance (secured using TLSv1.2).

    >>> def my_app(session, request, bodies):
    ...     return (200, 'OK', {}, b'hello, world')
    ...
    >>> from degu.server import SSLServer, build_server_sslctx
    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()
    >>> sslctx = build_server_sslctx(pki.server_sslconfig)
    >>> server = SSLServer(sslctx, ('127.0.0.1', 0), my_app)

    This subclass inherits all attributes and methods from :class:`Server`.

    The *sslctx* can be a pre-built `ssl.SSLContext`_, or a ``dict`` providing
    the *sslconfig* for :func:`build_server_sslctx()`.

    The *address* and *app*, along with any keyword-only *options*, are passed
    unchanged to the :class:`Server` constructor.

    .. attribute:: sslctx

        The *sslctx* argument provided to the contructor.

        Alternately, if the first argument provided to the constructor was an
        *sslconfig* ``dict``, this attribute will contain the
        `ssl.SSLContext`_ returned by :func:`build_server_sslctx()`.



.. _server-sslctx:

*sslctx*
''''''''


:func:`build_server_sslctx()`
-----------------------------

.. function:: build_server_sslctx(sslconfig)

    Build an `ssl.SSLContext`_ appropriately configured for server-side use.

    This function complements the client-side setup built with
    :func:`degu.client.build_client_sslctx()`.

    The *sslconfig* must be a ``dict`` instance, which must include at least two
    keys:

        *   ``'cert_file'`` --- a ``str`` providing the path of the server
            certificate file

        *   ``'key_file'`` --- a ``str`` providing the path of the server key
            file

    And must also include one of:

        *   ``'ca_file'`` and/or ``'ca_path'`` --- a ``str`` providing the path
            of the file or directory, respectively, containing the trusted CA
            certificates used to verify client certificates on incoming client
            connections

        *   ``'allow_unauthenticated_clients'`` --- if neither ``'ca_file'`` nor
            ``'ca_path'`` are provided, this must be provided and must be
            ``True``; this is to prevent accidentally allowing anonymous clients
            by merely omitting the ``'ca_file'`` and ``'ca_path'``

    For example, typical Degu P2P usage will use a server *sslconfig* something
    like this:

    >>> from degu.server import build_server_sslctx
    >>> sslconfig = {
    ...     'cert_file': '/my/server.cert',
    ...     'key_file': '/my/server.key',
    ...     'ca_file': '/my/client.ca',
    ... }
    >>> sslctx = build_server_sslctx(sslconfig)  #doctest: +SKIP

    Although you can directly build your own server-side `ssl.SSLContext`_, this
    function eliminates many potential security gotchas that can occur through
    misconfiguration.

    Opinionated security decisions this function makes:

        *   The *protocol* is unconditionally set to ``ssl.PROTOCOL_TLSv1_2``

        *   The *verify_mode* is set to ``ssl.CERT_REQUIRED``, unless
            ``'allow_unauthenticated_clients'`` is provided in the *sslconfig*
            (and is ``True``), in which case the *verify_mode* is set to
            ``ssl.CERT_NONE``

        *   The *options* unconditionally include ``ssl.OP_NO_COMPRESSION``,
            thereby preventing `CRIME-like attacks`_, and also allowing lower
            CPU usage and higher throughput on non-compressible payloads like
            media files

        *   The *ciphers* are unconditionally set to::

                'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'

    This function is also advantageous because the *sslconfig* is simple and
    easy to serialize/deserialize on its way to a new
    `multiprocessing.Process`_.  This means that your main process doesn't need
    to import any unnecessary modules or consume any unnecessary resources when
    a :class:`degu.server.SSLServer` will only be run in a subprocess.

    For unit testing and experimentation, consider using
    a :class:`degu.misc.TempPKI` instance, for example:

    >>> from degu.misc import TempPKI
    >>> pki = TempPKI()
    >>> sslctx = build_server_sslctx(pki.server_sslconfig)


RGI arguments
-------------

When the Degu server receives an incoming connection, it creates a new
:class:`Session` instance that will be associated with that connection for the
lifetime of the connection.

Then if your root application has an ``app.on_connect()`` connection handler,
it will be called with this new :class:`Session` instance as the first
argument::

    app.on_connect(session, sock) --> True/False

(The second argument will be the raw `socket.socket`_ or `ssl.SSLSocket`_
instance corresponding to the incoming connection.)

Finally for each request received through the connection, your ``app()`` request
handler will be called with still this exact same :class:`Session` instance as
the first argument::

    app(session, request, bodies) --> (status, reason, headers, body)

(The second argument will be a :class:`Request` namedtuple representing the
specific request, and the third argument will be the standard
:attr:`degu.base.bodies` namedtuple instance exposing the Bodies API, which will
always be the same for all requests and all connections for the lifetime of the
process.)

:class:`Request` instances expose request-level semantics to RGI server
applications, which is standard for any HTTP server application interface.

But :class:`Session` instances expose connection-level semantics to RGI server
applications, which is rather unusual and fairly unique to Degu.

Both are documented below.


:class:`Session`
''''''''''''''''

.. class:: Session(address, credentials=None, max_requests=None)

    An object used to represent an incoming socket connection to the server.

    .. note::

        It might seem more natural to call this a "connection", but that term
        was avoided to prevent confusing the "session" with the actual
        `socket.socket`_ instance or even a :class:`degu.client.Connection`
        instance.

    The three constructor arguments are all exposed as read-only attributes:

        * :attr:`Session.address`
        * :attr:`Session.credentials`
        * :attr:`Session.max_requests`

    A :class:`Session` also exposes two other read-only attributes:

        * :attr:`Session.requests`
        * :attr:`Session.store`

    Normally you wouldn't directly create a :class:`Session` yourself, but it
    can be handy to create them when unit testing your RGI applications.

    .. attribute:: address

        The socket address of the connecting client.

    .. attribute:: credentials

        The Unix credentials of the connecting client.

        This will be a ``(pid,uid,gid)`` 3-tuple when the connection was
        received over an ``AF_UNIX`` socket; otherwise this will be ``None``.

    .. attribute:: max_requests

        The maximum number of requests Degu will handle through this connection.

        Once this limit has been reached, the server will forcibly close the
        connection.

    ..  attribute:: requests

        The number of requests so far handled through this connection.

        This will initially be ``0``.

        After a request has been completely and successfully handled, the Degu
        sever will increment this counter (prior to reading the next request
        and calling your ``app()`` request handler).

    .. attribute:: store

        A ``dict`` that RGI applications can use for per-session storage.

        The go-to use-case for this is that a reverse-proxy application can
        store its client connection to the upstream HTTP server and reuse it on
        subsequent requests handled through the same connection (er, session).

        For example:

        >>> class ProxyApp:
        ...     def __init__(self, client):
        ...         self.client = client
        ... 
        ...     def __call__(self, session, request, bodies):
        ...         conn = session.store.get('conn')
        ...         if conn is None:
        ...             conn = self.client.connect()
        ...             session.store['conn'] = conn
        ...         return conn.request(*request[:4])
        ... 

        Hopefully this example helps make it clear the term "session" was chosen
        over "connection"... because otherwise things get confusing fast :D

        Although the :attr:`Session.store` attribute itself is read-only, the
        ``dict`` it returns is mutable and the same ``dict`` instance will be
        returned every time you access this attribute.

    .. method:: __repr__()

        Return a logging-friendly representation of the session.

        For example, the session corresponding to an ``AF_INET`` connection:

        >>> from degu.server import Session
        >>> session = Session(('127.0.0.1', 12345), None)
        >>> repr(session)
        "Session(('127.0.0.1', 12345))"

        (Notice that the *credentials* argument isn't included when ``None``.)

        Or a session corresponding to an ``AF_UNIX`` connection:

        >>> session = Session(b'\x0000222', (23848, 1000, 1000))
        >>> repr(session)
        "Session(b'\\x0000222', (23848, 1000, 1000))"
        
    



:class:`Request`
''''''''''''''''

.. class:: Request(method, uri, headers, body, script, path, query)

    A namedtuple used to represent an HTTP request.

    For example, the Degu server might call your ``app()`` request handler with
    something like this:

    >>> from degu.server import Request
    >>> Request('GET', '/foo', {}, None, [], ['foo'], None)
    Request(method='GET', uri='/foo', headers={}, body=None, script=[], path=['foo'], query=None)

    .. attribute:: method

        A ``str`` containing the HTTP request method. 

        Currently Degu only supports the ``'GET'``, ``'HEAD'``, ``'PUT'``,
        ``'POST'``, and ``'DELETE'`` methods.

    .. attribute:: uri

        A ``str`` containing the original, unparsed request URI.

    .. attribute:: headers

        A ``dict`` containing the request headers.

    .. attribute:: body

        The HTTP request body.

        This will be ``None`` when there is no request body.

        If the request body has a Content-Length, this will be a
        :class:`degu.base.Body` instance.

        Finally, if the request body uses "chunked" Transfer-Encoding, this will
        be a :class:`degu.base.ChunkedBody` instance.

    .. attribute:: script

        A ``list`` containing the previously processed parts of the URI.

        This corresponds to the mount point of the called RGI application or
        middleware.

        Currently Degu only supports mounting the root application at ``'/'``,
        so your root application will always be called with a *script* equal to
        ``[]``.

        However, as a request was routed to the current RGI application or
        middleware, path components from :attr:`Request.path` may have been
        shifted to :attr:`Request.script`, for example using
        :func:`degu.util.shift_path()`.

    .. attribute:: path

        A ``list`` containing the yet-to-be processed parts of the URI.

        This is the portion of the URI that the called RGI application or
        middleware is expected to handle.  This is initially derived from the
        URI.

        Some example URI and the resulting initial path::

            '/'        --> []
            '/foo'     --> ['foo']
            '/foo/'    --> ['foo', '']
            '/foo/bar' --> ['foo', 'bar']

        However, as a request was routed to the current RGI application or
        middleware, path components from :attr:`Request.path` may have been
        shifted to :attr:`Request.script`, for example using
        :func:`degu.util.shift_path()`.

    .. attribute:: query

        A ``str`` containing the query portion of the URI, or ``None``.

        Degu differentiates between "no query" vs merely an "empty query".

        When this is ``None``, it means the URI did not contain a ``'?'``.  When
        this is an empty ``''``, it means the final character in the URI was a
        ``'?'``.

        Some example URI and the resulting query::

            '/foo'     --> None
            '/foo?'    --> ''
            '/foo?bar' --> 'bar'
            '/foo?k=v' --> 'k=v'


.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket`: https://docs.python.org/3/library/socket.html
.. _`socket.socket.bind()`: https://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`socket.socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`ssl.SSLSocket`: https://docs.python.org/3/library/ssl.html#ssl.SSLSocket
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`socket.create_connection()`: https://docs.python.org/3/library/socket.html#socket.create_connection
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`CRIME-like attacks`: http://en.wikipedia.org/wiki/CRIME
.. _`perfect forward secrecy`: http://en.wikipedia.org/wiki/Forward_secrecy

