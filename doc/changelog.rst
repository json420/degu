Changelog
=========


0.7 (unreleased)
----------------


0.6 (June 2014)
---------------

Although Degu 0.6 brings a large number of breaking API changes, the high-level
server and client APIs are now (more or less) feature complete and can be (at
least cautiously) treated as API-stable; however, significant breakage and churn
should still be expected over the next few months in lower-level, internal, and
currently undocumented APIs.

Changes:

    * Consolidate previously scattered and undocumented RGI server application
      helper functions into the new :mod:`degu.util` module

    * Document some of the internal API functions in :mod:`degu.base` (note that
      none of these are API stable yet), plus document the new public IO
      abstraction classes:

        * :class:`degu.base.Body`

        * :class:`degu.base.BodyIter`

        * :class:`degu.base.ChunkedBody`

        * :class:`degu.base.ChunkedBodyIter`

    * As a result of the reworked IO abstraction classes (breaking change
      below), an incoming HTTP body can now be directly used as an outgoing HTTP
      body with no intermediate wrapper; this even further simplifies what it
      takes to implement an RGI reverse-proxy application

    * Degu and RGI now fully expose chunked transfer-encoding semantics,
      including the optional per-chunk extension; on both the input and output
      side of things, a chunk is now represented by a 2-tuple::

        (data, extension)

    * Largely rewrite the :doc:`rgi` specification to reflect the new
      connection-level semantics

    * Big update to the :doc:`tutorial` to cover request and response bodies,
      the IO abstraction classes, and chunked-encoding

    * Degu is now approximately 35% faster when it comes to writing an HTTP
      request or response preamble with 6 (or so) headers; the more headers, the
      bigger the performance improvement

    * Add ``./setup.py test --skip-slow`` option to skip the time-consuming (but
      important) live socket timeout tests... very handy for day-to-day
      development


Internal API changes:

    * ``read_lines_iter()`` has been replaced by
      :func:`degu.base.read_preamble()`

    * ``EmptyLineError`` has been renamed to :exc:`degu.base.EmptyPreambleError`

    * :func:`degu.base.read_chunk()` and :func:`degu.base.write_chunk()` now
      enforce a sane 16 MiB per-chunk data size limit

    * :func:`degu.base.read_preamble()` now allows up to 15 request or response
      headers (up from the previous 10 header limit)


Breaking public API changes:

    * If an RGI application object itself has an ``on_connect`` attribute, it
      must be a callable accepting two arguments (a *sock* and a *session*);
      when defined, ``app.on_connect()`` will be called whenever a new
      connection is recieved, before any requests have been handled for that
      connection; if ``app.on_connect()`` does not return ``True``, or if any
      unhandled exception occurs, the socket connection will be immediately
      shutdown without further processing; note that this is only a *breaking*
      API change if your application object happened to have an ``on_connect``
      attribute already used for some other purpose

    * RGI server applications now take two arguments when handling requests: a
      *session* and a *request*, both ``dict`` instances; the *request* argument
      now only contains strictly per-request information, whereas the
      server-wide and pre-connection information has been moved into the new
      *session* argument

    * Replace previously separate input and output abstractions with new unified
      :class:`degu.base.Body` and :class:`degu.base.ChunkedBody` classes for
      wrapping file-like objects, plus :class:`degu.base.BodyIter` and
      :class:`degu.base.ChunkedBodyIter` classes for wrapping arbitrary iterable
      objects

    * As a result of the above two breaking changes, the names under which these
      wrappers classes are exposed to RGI applications have changed, plus
      they're now in the new RGI *session* argument instead of the existing
      *request* argument:

        ==================================  ==================================
        Exposed via                         Degu implementation
        ==================================  ==================================
        ``session['rgi.Body']``             :class:`degu.base.Body`
        ``session['rgi.BodyIter']``         :class:`degu.base.BodyIter`
        ``session['rgi.ChunkedBody']``      :class:`degu.base.ChunkedBody`
        ``session['rgi.ChunkedBodyIter']``  :class:`degu.base.ChunkedBodyIter`
        ==================================  ==================================

    * The previous ``make_input_from_output()`` function has been removed; there
      is no need for this now that you can directly use any HTTP input body as
      an HTTP output body (for, say, a reverse-proxy application)

    * Iterating through a chunk-encoded HTTP input body now yields a
      ``(data, extension)`` 2-tuple for each chunk; likewise,
      ``body.readchunk()`` now returns a ``(data, extension)`` 2-tuple; however,
      there has been no change in the behavior of ``body.read()`` on
      chunk-encoded bodies

    * Iterables used as the source for a chunk-encoded HTTP output body now must
      yield a ``(data, extension)`` 2-tuple for each chunk

In terms of the RGI request handling API, this is how you implemented a
*hello, world* RGI application in Degu 0.5 and earlier:

>>> def hello_world_app(request):
...     return (200, 'OK', {'content-length': 12}, b'hello, world')
...

As of Degu 0.6, it must now be implemented like this:

>>> def hello_world_app(session, request):
...     return (200, 'OK', {'content-length': 12}, b'hello, world')
...

Or here's a version that uses the connection-handling feature new in Degu 0.6:

>>> class HelloWorldApp:
... 
...     def __call__(self, session, request):
...         return (200, 'OK', {'content-length': 12}, b'hello, world')
... 
...     def on_connect(self, sock, session):
...         return True
... 

If the ``app.on_connect`` attribute exists, ``None`` is also a valid value.  If
needed, this allows you to entirely disable the connection handler in a
subclass.  For example:

>>> class HelloWorldAppSubclass(HelloWorldApp):
...     on_connect = None
... 

For more details, please see the :doc:`rgi` specification.



0.5 (May 2014)
--------------

Changes:

    * Greatly expand and enhance documentation for the :mod:`degu.client` module

    * Modest update to the :mod:`degu.server` module documentation, in
      particular to cover HTTP over ``AF_UNIX``

    * Add a number of additional sanity and security checks in
      :func:`degu.client.build_client_sslctx()`, expand its unit tests
      accordingly

    * Likewise, add additional checks in
      :func:`degu.server.build_server_sslctx()`, expand its unit tests
      accordingly

    * :meth:`degu.client.Connection.close()` now only calls
      ``socket.socket.shutdown()``, which is more correct, and also eliminates
      annoying exceptions that could occur when a
      :class:`degu.client.Connection` (previously ``Client`` or ``SSLClient``)
      is garbage collected immediately prior to a script exiting

Breaking public API changes:

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

    * In the near future, the Degu client API will support an  ``on_connect()``
      handler to allow 3rd party applications to do things like extended
      per-connection authentication; splitting the client creation out from the
      connection creation allows most 3rd party code to remain oblivious as to
      whether such an ``on_connect()`` handler is in use (as most code can
      merely create connections using the provided client, rather than
      themselves creating clients)

