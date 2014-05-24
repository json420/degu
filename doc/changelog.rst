Changelog
=========


0.5 (May 2014)
--------------

Changes:

    * Greatly expand and enhance documentation for the :mod:`degu.client` module

    * Add a number of additional sanity and security checks in
      :func:`degu.client.build_client_sslctx()`, update its unit tests
      accordingly

    * :meth:`degu.client.Connection.close()` now only calls
      ``socket.socket.shutdown()``, which is more correct, and also eliminates
      annoying exceptions that could occur when the
      :class:`degu.client.Connection` (previously ``Client`` or ``SSLClient``)
      is garbage collected immediately prior to a script exiting

Breaking API changes:

    * The ``Connection`` namedtuple has been replaced by the
      :class:`degu.client.Connection` class

    * ``Client.request()`` has been moved to
      :meth:`degu.client.Connection.request()`

    * ``Client.close()`` has been moved to
      :meth:`degu.client.Connection.close()`

Whereas previously you'd do something like this::

    from degu.client import Client
    client = Client(('127.0.0.1', 5984))
    client.request('GET', '/')
    client.close()

As of Degu 0.5, you now need to do this::

    from degu.client import Client
    client = Client(('127.0.0.1', 5984))
    conn = client.connect()
    conn.request('GET', '/')
    conn.close()

:class:`degu.client.Client` and :class:`degu.client.SSLClient` instances are
now stateless and thread-safe, do not themselves reference any socket resources.
On the other hand, :class:`degu.client.Connection` instances are statefull and
are *not* thread-safe.

Two things motivated these breaking API changes:

    * Justifiably, ``Client`` and ``SSLClient`` do rather thorough type and
      value checking on their constructor arguments; whereas previously you had
      to create a client instance per connection (eg, per thread), now you can
      create an arbitrary number of connections from a single client; this means
      that connections now are faster to create and have a lower per-connection
      memory footprint

    * In the near future, the Degu client API will support an 
      ``on_connection()`` handler to allow 3rd party applications to do things
      like extended per-connection authentication; splitting the client creation
      from the connection creation allows most 3rd party code to remain
      oblivious as to whether such a ``on_connection()`` handler is in use (as
      most code can merely create connections using the provided client, rather
      than themselves creating clients)

