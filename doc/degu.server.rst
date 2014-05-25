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
>>> conn = client.connect()
>>> response = conn.request('GET', '/')
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
can be:

    * A ``(host, port)`` 2-tuple for ``AF_INET``, where the *host* is an IPv4 IP

    * A ``(host, port, flowinfo, scopeid)`` 4-tuple for ``AF_INET6``, where the
      *host* is an IPv6 IP

    * An ``str`` instance providing the filename of an ``AF_UNIX`` socket

    * A ``bytes`` instance providing the Linux abstract name of an ``AF_UNIX``
      socket (typically an empty ``b''`` so that the abstract name is assigned
      by the kernel)

In all cases, your *address* argument is passed directly to
`socket.socket.bind()`_.  Among other things, this gives you access to full
IPv6 address semantics when using an ``AF_INET6`` 4-tuple, including the
*scopeid* needed for `link-local addresses`_.

Typically you'll run your ``AF_INET`` or ``AF_INET6`` Degu server on a random,
unprivileged port, so if your *address* is a 2-tuple or 4-tuple, you'll
typically supply ``0`` for the *port*, in which case a random port will be
assigned by the kernel.

However, after you create your :class:`Server` or :class:`SSLServer` instance,
you'll need to know what random port was assigned by the kernel (for example, so
you can advertise this port to peers on the local network).

The :attr:`Server.address` instance attribute will be the value returned by
`socket.socket.getsockname()`_ for the socket upon which your server is
listening.  For example, assuming port ``54321`` was assigned, the
:attr:`Server.address` would be something like this for ``AF_INET``::

    ('127.0.0.1', 54321)

Or something like this for ``AF_INET6``::

    ('::1', 54321, 0, 0)

Likewise, you'll typically bind your ``AF_INET`` or ``AF_INET6`` Degu server to
either the special loopback-IP or the special any-IP addresses.

For example, these are the two most common ``AF_INET`` 2-tuple *address*
values, for the looback-IP and the any-IP, respectively::

    ('127.0.0.1', 0)
    ('0.0.0.0', 0)

And these are the two most common ``AF_INET6`` 4-tuple *address* values, for the
looback-IP and the any-IP, respectively::

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

The :attr:`Server.address` instance attribute would then contain the ``AF_UNIX``
Linux abstract socket name assigned by the kernel, something like::

    b'\x0000022'




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


Functions
---------

.. autofunction:: build_server_sslctx


.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
.. _`socket.socket.bind()`: https://docs.python.org/3/library/socket.html#socket.socket.bind
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`socket.socket`: https://docs.python.org/3/library/socket.html#socket-objects
.. _`socket.socket.getsockname()`: https://docs.python.org/3/library/socket.html#socket.socket.getsockname
.. _`socket.create_connection()`: https://docs.python.org/3/library/socket.html#socket.create_connection
