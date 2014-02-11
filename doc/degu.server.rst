:mod:`degu.server` --- HTTP Server
==================================

.. module:: degu.server
   :synopsis: Embedded HTTP Server


.. class:: Server(app, address=('::1', 0, 0, 0))

    A light-weight, embedded HTTP server.

    .. attribute:: app

        The :doc:`rgi` application provided when the instance was created.

    .. attribute:: sock

        The ``socket.socket`` instance upon which the server is listening.

    .. attribute:: address

        The address as returned by ``getsockname()`` on the above :attr:`sock`.

        Note this wont necessarily match the *address* provided when the
        instance was created.  As Degu is designed for per-user server instances
        on dynamic ports, you typically specify port ``0`` in the *address*,
        using something like this::

            ('::', 0, 0, 0)

        In which case this address attribute will contain the random port
        assigned by the operating system, something like this::

            ('::', 40505, 0, 0)



.. class:: SSLServer(sslctx, app, address=('::1', 0, 0, 0))
