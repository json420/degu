:mod:`degu.server` --- HTTP Server
==================================

.. module:: degu.server
   :synopsis: Embedded HTTP Server

As a quick example, say you have this simple RGI application:

>>> def hello_world_app(request):
...     if request['method'] not in {'GET', 'HEAD'}:
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'Hello, world!'
...     headers = {'content-length': len(body)}
...     if request['method'] == 'GET':
...         return (200, 'OK', headers, body)
...     return (200, 'OK', headers, None)  # No response body for HEAD
...

You can create a :class:`Server` instance like this:

>>> from degu.server import Server
>>> server = Server(('::1', 0, 0, 0), hello_world_app)

And then start the server by calling :meth:`Server.serve_forever()`.

However, note that :meth:`Server.serve_forever()` will block the calling thread
forever.  When embedding Degu in desktop and mobile applications, it's
recommended to run your server in its own ``multiprocessing.Process``, which you
can easily do using the :func:`start_server()` helper function, for example:

>>> (process, address) = start_server(None, hello_world_app)


However, for testing and experimentation, it's easy to use a TempServer

>>> from degu.misc import TempServer
>>> tmpserver = TempServer(None, hello_world_app)
>>> client = tmpserver.get_client()
>>> response = client.request('GET', '/')
>>> response.status
200
>>> response.headers
{'content-length': 13}
>>> response.body.read()
b'Hello, world!'

Bind *address*
--------------

Both :class:`Server` and :class:`SSLServer` take an *address* argument, which
must be a 4-tuple for IPv6 and a 2-tuple for IPv4.  This *address* argument is
passed directly to `socket.socket.bind()`_, thereby giving you access to full IPv6
address semantics, including the *scopeid* needed for `link-local addresses`_.

.. note::

    Although Python's `socket.socket.bind()`_ will accept a 2-tuple for an
    ``AF_INET6`` family socket, Degu does not allow this.  An IPv6 *address*
    must always be a 4-tuple.  This restriction gives Degu a simple, unambiguous
    way of selecting between the ``AF_INET6`` and ``AF_INET`` families, without
    needing to inspect ``address[0]`` (the host portion).


Constants
---------

:mod:`degu.server` includes handy constants with some common IPv6 and IPv4
*address* tuples:

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


Functions
---------

.. function:: start_server(address, build_func, *build_args)

    Start a :class:`Server` in a new process.

    The return value is a ``(process, address)`` tuple.


.. function:: start_sslserver(sslconfig, address, build_func, *build_args)

    Start a :class:`SSLServer` in a new process.

    The return value is a ``(process, address)`` tuple.


The :class:`Server` class
----------------------------

.. class:: Server(address, app)

    As discussed above, the *address* argument must be a 4-tuple for IPv6 and a
    2-tuple for IPv4.

    The *app* argument must be a callable that implements the :doc:`rgi`.

    .. attribute:: sock

        The `socket.socket`_ instance upon which the server is listening.

    .. attribute:: address

        The address as returned by `socket.socket.getsockname()`_.

        Note this wont necessarily match the *address* provided when the server
        instance was created.  As Degu is designed for per-user server instances
        on dynamic ports, you typically specify port ``0`` in the *address*,
        using something like this::

            ('::1', 0, 0, 0)

        In which case this address attribute will contain the random port
        assigned by the operating system, something like this::

            ('::1', 40505, 0, 0)

    .. attribute:: app

        The RGI application callable provided when the instance was created.

    .. method:: serve_forever()

        Start the server in multi-threaded mode.

        The caller will block forever.


The :class:`SSLServer` class
----------------------------

.. class:: SSLServer(sslctx, addresss, app)


.. _`socket.socket.bind()`: http://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`socket.socket`: http://docs.python.org/3/library/socket.html#socket-objects
.. _`socket.socket.getsockname()`: http://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`socket.create_connection()`: http://docs.python.org/3/library/socket.html#socket.create_connection
