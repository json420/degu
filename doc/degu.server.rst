:mod:`degu.server` --- HTTP Server
==================================

.. module:: degu.server
   :synopsis: Embedded HTTP Server


As a quick example, say you have this :doc:`rgi` application:

>>> def hello_world_app(session, request, bodies):
...     if request['method'] not in {'GET', 'HEAD'}:
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'hello, world'
...     headers = {'content-length': len(body), 'content-type': 'text/plain'}
...     if request['method'] == 'GET':
...         return (200, 'OK', headers, body)
...     return (200, 'OK', headers, None)  # No response body for HEAD

(For a short primer on implementing RGI server applications, please see
:ref:`server-app-callable`.)

You can create a :class:`Server` like this:

>>> from degu.server import Server
>>> server = Server(('::1', 0, 0, 0), hello_world_app)

And then start the server by calling :meth:`Server.serve_forever()`.

However, note that :meth:`Server.serve_forever()` will block the calling thread
forever.  When embedding Degu within another application, it's generally best to
run your server in its own `multiprocessing.Process`_, which you can easily do
using the :func:`degu.start_server()` helper function, for example:

>>> from degu import start_server
>>> (process, address) = start_server(('::1', 0, 0, 0), None, hello_world_app)

You can create a suitable :class:`degu.client.Client` with the returned
*address* like this:

>>> from degu.client import Client
>>> client = Client(address)
>>> conn = client.connect()
>>> response = conn.request('GET', '/')
>>> response.body.read()
b'hello, world'

Running your Degu server in its own process has many advantages.  It means there
will be no thread contention between the Degu server process and your main
application process, and it also means you can forcibly and instantly kill the
server process whenever you need (something you can't do with a thread).  For
example, to kill the server process we just created:

>>> process.terminate()
>>> process.join()



:class:`Server` class
---------------------

.. class:: Server(address, app, **options)

    An HTTP server instance.

    The *address* argument specifies the socket address upon which the server
    will listen.  It can be a 2-tuple for ``AF_INET`` (IPv4), a 4-tuple for
    ``AF_INET6`` (IPv6), or an ``str`` or ``bytes`` instance for ``AF_UNIX``.
    See :ref:`server-address` for details.

    The *app* argument provides your :doc:`rgi` (RGI) server application.  It
    must be a callable object (called to handle each HTTP request), and can
    optionally have a callable ``app.on_connect()`` attribute (called to handle
    each TCP connection).  See :ref:`server-app-callable` for details.

    Finally, you can provide keyword-only *options* to override the defaults for
    a number of tunable server runtime parameters.  See :ref:`server-options`
    for details.

    .. attribute:: address

        The bound server address as returned by `socket.socket.getsockname()`_.

        Note that this wont necessarily match the *address* argument provided to
        the constructor.  As Degu is designed for per-user server instances
        running on dynamic ports, you typically specify port ``0`` in an
        ``AF_INET`` or ``AF_INET6`` *address* argument::

            ('127.0.0.1', 0)  # AF_INET (IPv4)
            ('::1', 0, 0, 0)  # AF_INET6 (IPv6)

        In which case the :attr:`Server.address` attribute will contain the port
        assigned by the operating system.  For example, assuming port ``12345``
        assigned::

            ('127.0.0.1', 12345)  # AF_INET (IPv4)
            ('::1', 12345, 0, 0)  # AF_INET6 (IPv6)

    .. attribute:: app

        The *app* argument provided to the constructor.

    .. attribute:: options

        A ``dict`` containing the server configuration options.

        This will contain the values of any keyword-only *options* provided to
        the constructor, and will otherwise contain the default values for all
        other *options* that weren't explicitly provided.

    .. attribute:: sock

        The `socket.socket`_ instance upon which the server is listening.

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



.. _server-app-callable:

*app*
'''''

Both :class:`Server` and :class:`SSLServer` take an *app* argument, by which you
provide your HTTP request handler, and optionally provide a TCP connection
handler.

Here's a quick primer on implementing Degu server applications, but for full
details, please see the :doc:`rgi` specification.


**HTTP request handler:**

Your *app* must be a callable object that accepts three arguments, for example:

>>> def my_rgi_app(session, request, bodies):
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

>>> class MyRGIApp:
...     def __call__(self, session, request, bodies):
...         return (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')
... 
...     def on_connect(self, sock, session):
...         return True
...

The *sock* argument will be a `socket.socket`_ when running your app in a
:class:`Server`, or an `ssl.SSLSocket`_ when running your app in an 
:class:`SSLServer`.

Finally, the *session* argument will be same ``dict`` instance passed to your
``app()`` HTTP request handler, something like this::

    session = {
        'client': ('127.0.0.1', 12345),
    }

Your ``app.on_connect()`` will be called after a new TCP connection has been
accepted, but before any HTTP requests have been handled via that TCP
connection.

It must return ``True`` when the connection should be accepted, or return
``False`` when the connection should be rejected.

If your *app* has an ``on_connect`` attribute that is *not* callable, it must be
``None``.  This allows you to disable the ``app.on_connect()`` handler in a
subclass, for example:

>>> class MyRGIAppSubclass(MyRGIApp):
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

>>> def my_rgi_app(session, request, bodies):
...     body = session.get('__body')
...     if body is None:
...         body = b'hello, world'
...         session['__body'] = body
...     return (200, 'OK', {'content-type': 'text/plain'}, body)

Likewise, if your ``app.on_connect()`` TCP connection handler adds anything to
the *session*, it should prefix the key with ``'_'`` (underscore).  For example:

>>> class MyRGIApp:
...     def __call__(self, session, request, bodies):
...         if session.get('_user') != 'admin':
...             return (403, 'Forbidden', {}, None)
...         return (200, 'OK', {'content-type': 'text/plain'}, b'hello, world')
...
...     def on_connect(self, sock, session):
...         # Somehow authenticate the user who made the connection:
...         session['_user'] = 'admin'
...         return True



.. _server-options:

*options*
'''''''''

Both :class:`Server` and :class:`SSLServer` accept keyword *options* by which
you can override certain configuration defaults.

The following server configuration *options* are supported:

    *   **bodies** --- a namedtuple exposing the four IO wrapper classes used to
        construct HTTP request and response bodies

    *   **timeout** --- server socket timeout in seconds; must be a positve
        ``int`` or ``float`` instance

    *   **max_connections** --- maximum number of concurrent TCP connections the
        server will accept; once this maximum has been reached, subsequent
        connections will be rejected till one or more existing connections are
        closed; this option directly effects the maximum amount of memory Degu
        can consume for in-flight per-connection and per-request data; it must
        be a positive ``int``

    *   **max_requests_per_connection** --- maximum number of HTTP requests that
        can be handled through a single TCP connection before that connection
        is forcibly closed by the server; a lower value will minimize the impact
        of heap fragmentation and will keep the memory usage flatter over time;
        a higher value can provide better throughput when a large number of
        small requests and responses need to travel in quick succession through
        the same TCP connection (typical for CouchDB-style structured data
        sync); it must be a positive ``int``

Unless you override any of them, the default server configuration *options*
are::

    server_options = {
        'bodies': degu.base.DEFAULT_BODIES,
        'timeout': 15,
        'max_connections': 25,
        'max_requests_per_connection': 100,
    }

Also see the client :ref:`client-options`.



:class:`SSLServer` subclass
---------------------------

.. class:: SSLServer(sslctx, address, app, **options)

    An HTTPS server instance (secured using TLSv1.2).

    This subclass inherits all attributes and methods from :class:`Server`.

    The *sslctx* argument must be an `ssl.SSLContext`_ instance appropriately
    configured for server-side use.

    Alternatively, if the *sslctx* argument is a ``dict`` instance, it is
    interpreted as the server *sslconfig* and the actual `ssl.SSLContext`_
    instance will be built automatically by calling
    :func:`build_server_sslctx()`.

    The *address* and *app* arguments, along with any keyword-only *options*,
    are passed unchanged to :class:`Server()`.

    .. attribute:: sslctx

        The *sslctx* argument provided to the contructor.



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

        * ``'cert_file'`` --- an ``str`` providing the path of the server
          certificate file

        * ``'key_file'`` --- an ``str`` providing the path of the server key
          file

    And can optionally include either of the keys:

        * ``'ca_file'`` and/or ``'ca_path'`` --- an ``str`` providing the path
          of the file or directory, respectively, containing the trusted CA
          certificates used to verify client certificates on incoming client
          connections

        * ``'allow_unauthenticated_clients'`` --- if neither ``'ca_file'`` nor
          ``'ca_path'`` are provided, this must be provided and must be
          ``True``; this is to prevent accidentally allowing anonymous clients
          by merely omitting the ``'ca_file'`` and ``'ca_path'``

    For example, typical Degu P2P usage will use an *sslconfig* something like
    this:

    >>> from degu.server import build_server_sslctx
    >>> sslconfig = {
    ...     'cert_file': '/my/server.cert',
    ...     'key_file': '/my/server.key',
    ...     'ca_file': '/my/client.ca',
    ... }
    >>> sslctx = build_server_sslctx(sslconfig)  #doctest: +SKIP

    Although you can directly build your own server-side `ssl.SSLContext`_, use
    of this function eliminates many potential security gotchas that can occur
    through misconfiguration.

    Opinionated security decisions this function makes:

        * The *protocol* is unconditionally set to ``ssl.PROTOCOL_TLSv1_2``

        * The *verify_mode* is set to ``ssl.CERT_REQUIRED``, unless
          ``'allow_unauthenticated_clients'`` is provided in the *sslconfig*
          (and is ``True``), in which case the *verify_mode* is set to
          ``ssl.CERT_NONE``

        * The *sslconfig* unconditionally include ``ssl.OP_NO_COMPRESSION``,
          thereby preventing `CRIME-like attacks`_, and also allowing lower
          CPU usage and higher throughput on non-compressible payloads like
          media files

        * The *cipher* is unconditionally set to
          ``'ECDHE-RSA-AES256-GCM-SHA384'``




.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.bind()`: https://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`socket.socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`ssl.SSLSocket`: https://docs.python.org/3/library/ssl.html#ssl.SSLSocket
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`socket.create_connection()`: https://docs.python.org/3/library/socket.html#socket.create_connection
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`CRIME-like attacks`: http://en.wikipedia.org/wiki/CRIME
.. _`perfect forward secrecy`: http://en.wikipedia.org/wiki/Forward_secrecy

