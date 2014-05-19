:mod:`degu.client` --- HTTP Client
==================================

.. module:: degu.client
   :synopsis: Low-level HTTP client

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

In some circumstance you might want to explicitly close a connection using
:meth:`Connection.close()`, although this will likewise be done automatically
when the connection instance is garbage collected:

>>> conn.close()



The *address* argument
----------------------

Both :class:`Client` and :class:`SSLClient` take an *address* argument, which
can be a:

    * A ``(host, port)`` 2-tuple with an IPv4 IP, an IPv6 IP, or a DNS domain
      name

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple with a fully specified IPv6
      address

    * An ``str`` instance providing the filename of an ``AF_UNIX`` socket

    * A ``bytes`` instance providing the Linux abstract name of an ``AF_UNIX``
      socket
 

If your *address* is a ``(host, port)`` 2-tuple, it's passed directly to
`socket.create_connection()`_ when creating a connection.  The *host* can be an
IPv6 IP, an IPv4 IP, or a DNS name.  For example, these are all valid 2-tuple
*address* values::

    ('2001:4860:4860::8888', 80)
    ('8.8.8.8', 80)
    ('www.example.com', 80)

If your *address* is a ``(host, port, flowinfo, scopeid)`` 4-tuple, it's passed
directly to `socket.socket.connect()`_ when creating a connection, thereby
giving you access to full IPv6 address semantics, including the *scopeid* needed
for `link-local addresses`_.  In this case the *host* must be an IPv6 IP.  For
example, this *address* would connect to a server listening on a link-local
address::

    ('fe80::e8b:fdff:fe75:402c', 80, 0, 3)



:class:`Client` class
---------------------

.. class:: Client(address, base_headers=None)

    Represents an HTTP server to which Degu can make client connections.

    *address* must be a 2-tuple, a 4-tuple, an ``str``, or a ``bytes`` instance.

    *base_headers* must be ``None`` or a ``dict`` instance.

    Note that headers in *base_headers* will unconditionally override the same
    headers should they be passed to :meth:`Connection.request()`.

    A :class:`Client` instance is stateless and thread-safe.  It contains the
    information needed to create actual :class:`Connection` instances, but does
    not itself create or reference any socket resources.

    .. attribute:: address

        The *address* passed to the constructor.

    .. attribute:: base_headers

        The *base_headers* passed to the constructor.

    .. method:: connect()

        Returns a :class:`Connection` instance.



:class:`SSLClient` class
------------------------

.. class:: SSLClient(sslctx, address, base_headers=None)

    Represents an HTTPS server to which Degu can make client connections.

    This subclass inherits all attributes and methods from :class:`Client`.

    *sslctx* must be an ``ssl.SSLContext`` instance configured for
    ``ssl.PROTOCOL_TLSv1_2``.

    The *address* and *base_headers* arguments are passed to the
    :class:`Client` constructor unchanged.

    An :class:`SSLClient` instance is stateless and thread-safe.  It contains
    the information needed to create actual :class:`Connection` instances, but
    does not itself create or reference any socket resources.

    .. attribute:: sslctx

        The *sslctx* passed to the constructor.



:class:`Connection` class
-------------------------

.. class:: Connection(sock, base_headers)

    Represents a specific connection to an HTTP (or HTTPS) server.

    Note that connections are created using :meth:`Client.connect()` rather than
    by directly creating an instance of this class.

    A :class:`Connection` is statefull and is *not* thread-safe.

    .. attribute :: closed

        Initially ``False``, but will be ``True`` once closed.

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
        exception occurs in :meth:`Connection.request()`, and likewise
        automatically closed when the connection instance is garbage collected.

    .. method:: request(method, uri, headers=None, body=None)



:class:`Response` namedtuple
----------------------------

.. class:: Response(status, reason, headers, body)

    HTTP Response nametuple returned by :meth:`Connection.request()`.

    For example, :meth:`Connection.request()` might return something like this:

    >>> from degu.client import Response
    >>> Response(200, 'OK', {}, None)
    Response(status=200, reason='OK', headers={}, body=None)

    Note that as a namedtuple, :class:`Response` doesn't do any type checking or
    argument validation itself.  The nature of the following attributes rely
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



.. _`socket.create_connection()`: http://docs.python.org/3/library/socket.html#socket.create_connection
.. _`socket.socket.connect()`: http://docs.python.org/3/library/socket.html#socket.socket.connect
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
