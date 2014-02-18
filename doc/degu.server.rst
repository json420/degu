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

You can create a :class:`Server` instance like this:

>>> from degu.server import Server
>>> server = Server(('::1', 0, 0, 0), hello_world_app)

And then start the server by calling :meth:`Server.serve_forever()`.

However, note that :meth:`Server.serve_forever()` will block the calling thread
forever.  When embedding Degu in desktop and mobile applications, it's best to
run your server in its own `multiprocessing.Process`_, which you can easily do
using the :func:`degu.start_server()` helper function, for example:

>>> from degu import start_server
>>> (process, address) = start_server(('::1', 0, 0, 0), None, hello_world_app)

You can create a suitable :class:`degu.client.Client` instance with the returned
*address* like this:

>>> from degu.client import Client
>>> client = Client(address)
>>> response = client.request('GET', '/')
>>> response.body.read()
b'Hello, world!'

Running your Degu server in its own process has many advantages.  It means there
will be no thread contention between the Degu server process and your main
application process, and it also means you can forcibly and instantly kill the
server process whenever you need (something you can't do with a thread).  For
example, to kill the server process we just created:

>>> process.terminate()
>>> process.join()


Bind *address*
--------------

Both :class:`Server` and :class:`SSLServer` take an *address* argument, which
must be a 4-tuple for IPv6 or a 2-tuple for IPv4.  This *address* argument is
passed directly to `socket.socket.bind()`_, thereby giving you access to full
IPv6 address semantics, including the *scopeid* needed for
`link-local addresses`_.

.. note::

    Although Python's `socket.socket.bind()`_ will accept a 2-tuple for an
    ``AF_INET6`` family socket, Degu does not allow this.  An IPv6 *address*
    must always be a 4-tuple.  This restriction gives Degu a simple, unambiguous
    way of selecting between the ``AF_INET6`` and ``AF_INET`` families, without
    needing to inspect ``address[0]`` (the host portion).

Typically you will use Degu for per-user server instances listening on random,
unprivileged ports (as opposed to system-wide server instances listening on
static, privileged ports).  In this case, ``address[1]`` (the port) should be
``0``.  For example, to bind to the IPv6 any-IP address, you would specify this
*address*::

    ('::', 0, 0, 0)

However, after you create your :class:`Server` or :class:`SSLServer` instance,
you'll need to know what random port was assigned by the operating system (for
example, so you can advertise this port to peers on the local network).

The :attr:`Server.address` instance attribute will be the 4-tuple or 2-tuple
returned by `socket.socket.getsockname()`_ for the socket upon which your
server is listening.  In our example, assuming port ``54321`` was assigned,
the :attr:`Server.address` would be::

    ('::', 54321, 0, 0)


The :class:`Server` class
-------------------------

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


.. _`multiprocessing.Process`: http://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.bind()`: http://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`socket.socket`: http://docs.python.org/3/library/socket.html#socket-objects
.. _`socket.socket.getsockname()`: http://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`socket.create_connection()`: http://docs.python.org/3/library/socket.html#socket.create_connection
