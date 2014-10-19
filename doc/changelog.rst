Changelog
=========


0.10 (unreleased)
-----------------

This *may* end up being the API stable Degu 1.0 release ``:D``


Breaking API changes:

    *   Change order of RGI ``app.on_connect()`` arguments from::

            app.on_connect(sock, session)

        To::

            app.on_connect(session, sock)

        Especially when you look at the overall API structurally, this change
        clearly makes sense.  See the new ``Degu-API.svg`` diagram in the Degu
        source tree for details.

    *   :meth:`degu.client.Connection.request()` now requires the *headers* and
        *body* arguments always to be provided; ie., the method signature has
        changed from::

            Connection.request(method, uri, headers=None, body=None)

        To::

            Connection.request(method, uri, headers, body)

        Although this means some code is a bit more verbose, it forces people to
        practice the full API and means that any given example someone
        encounters illustrates the full client request API; ie., this is always
        clear::

            conn.request('GET', '/', {}, None)

        Whereas this leaves a bit too much to the imagination when trying to
        figure out how to specify the request headers and request body::

            conn.request('GET', '/')

        This seems especially important as the order of the *headers* and *body*
        are flipped in Degu compared to `HTTPConnection.request()`_ in the
        Python standard library::

            HTTPConnection.request(method, url, body=None, headers={})

        The reason Degu flips the order is so that its API faithfully reflects
        the HTTP wire format... Degu arguments are always in the order that they
        are serialized in the TCP stream.  A goal has always been that if you
        know the HTTP wire format, it should be extremely easy to map that
        understanding into the Degu API.

        Post Degu 1.0, we could always again make the *headers* and *body*
        optional without breaking backword compatibility, but the reverse isn't
        true.  So we'll let this experiment run for a while, and then
        reevaluate.

    *   :class:`degu.client.Client` and :class:`degu.client.SSLClient` now
        accept generic and easily extensible keyword-only *options*::

            Client(address, **options)
            SSLClient(sslctx, address, **options)

        This means that you can no longer supply the *base_headers* as a
        positonal argument, only as a keyword argument.  See the client
        :ref:`client-options` for details.

    *   Likewise, :func:`degu.client.create_client()` and
        :func:`degu.client.create_sslclient()` now accept the same keyword-only
        *options*::

            create_client(url, **options)
            create_sslclient(sslctx, url, **options)

        Again, this means that you can no longer supply the *base_headers* as a
        positional argument, only as a keyword argument.


Other changes:

    *   The RGI *request* argument now includes a ``uri`` item, which will be
        the complete, unparsed URI from the request line, for example::

            request = {
                'method': 'GET',
                'uri': '/foo/bar/baz?stuff=junk',
                'script': ['foo'],
                'path': ['bar', 'baz'],
                'query': 'stuff=junk',
                'headers': {'accept': 'text/plain'},
                'body': None,
            }

        ``request['uri']`` was added so that RGI validation middleware can check
        that the URI was properly parsed and that any path shifting was done
        correctly.  It's also handy for logging.

    *   :class:`degu.server.Server` and :class:`degu.server.SSLServer` now also
        accepts generic and easily extensible keyword-only *options*::

            Server(address, app, **options)
            SSLServer(sslctx, address, app, **options)

        See the server :ref:`server-options` for details.



0.9 (September 2014)
--------------------

`Download Degu 0.9`_

Security fixes:

    *   :func:`degu.base.read_preamble()` now carefully restricts what bytes are
        allowed to exist in the first line, header names, and header values; in
        particular, this function now prevents the NUL byte (``b'\x00'``) from
        being included in any decoded ``str`` objects; for details, please see
        :doc:`security`

    *   :func:`degu.base.read_chunk()` likewise prevents the NUL byte
        (``b'\x00'``) from being included in the optional per-chunk extension

    *   :class:`degu.server.Server` now limits itself to 100 active threads (ie,
        100 concurrent connections) to prevent unbounded resource usage; this is
        hard-coded in 0.9 but will be configurable in 1.0


Breaking API changes:

    *   The RGI request signature is now ``app(session, request, bodies)``, and
        wrapper classes like ``session['rgi.Body']`` have moved to
        ``bodies.Body``, etc.

        For example, this Degu 0.8 RGI application::

            def my_file_app(session, request):
                myfile = open('/my/file', 'rb')
                body = session['rgi.Body'](myfile, 42)
                return (200, 'OK', {}, body)

        Is implemented like this in Degu 0.9::

            def my_file_app(session, request, bodies):
                myfile = open('/my/file', 'rb')
                body = bodies.Body(myfile, 42)
                return (200, 'OK', {}, body)

        The four HTTP body wrapper classes are now exposed as:

            ==========================  ==================================
            Exposed via                 Degu implementation
            ==========================  ==================================
            ``bodies.Body``             :class:`degu.base.Body`
            ``bodies.BodyIter``         :class:`degu.base.BodyIter`
            ``bodies.ChunkedBody``      :class:`degu.base.ChunkedBody`
            ``bodies.ChunkedBodyIter``  :class:`degu.base.ChunkedBodyIter`
            ==========================  ==================================

    *   The following four items have been dropped from the RGI *session*
        argument::

            session['rgi.version']  # eg, (0, 1)
            session['scheme']       # eg, 'https'
            session['protocol']     # eg, 'HTTP/1.1'
            session['server']       # eg, ('0.0.0.0', 12345)

        Although inspired by equivalent information in the WSGI *environ*, they
        don't seem particularly useful for the P2P REST API use case that Degu
        is focused on; in order to minimize the stable API commitments we're
        making for Degu 1.0, we're removing them for now, but we're open to
        adding any of them back post 1.0, assuming there is a good
        justification.


Other changes:

    *   Move ``_degu`` module to ``degu._base`` (the C extension)

    *   Rename ``degu.fallback`` module to ``degu._basepy`` (the pure-Python
        reference implementation)

    *   To keep memory usage flatter over time, :class:`degu.server.Server()`
        now unconditionally closes a connection after 5,000 requests have been
        handled; this is hard-coded in 0.9 but will be configurable in 1.0

    *   :class:`degu.base.Body()` now takes optional *iosize* kwarg; which
        defaults to :data:`degu.base.FILE_IO_BYTES`

    *   Add :meth:`degu.base.Body.write_to()` method to :class:`degu.base.Body`
        and its friends; this gives the HTTP body wrapper API greater
        composability, particularly useful should a Degu client or server use
        the *bodies* implementation from a other independent project


Performance improvements:

    *   The C implementation of :func:`degu.base.read_preamble()` is now around
        42% faster; this speed-up is thanks to decoding and case-folding the
        header keys in a single pass rather than using ``str.casefold()``, plus
        thanks to calling ``rfile.readline()`` using ``PyObject_Call()`` with
        pre-built argument tuples instead of ``PyObject_CallFunctionObjArgs()``
        with pre-built ``int`` objects

    *   :func:`degu.server.write_response()` is now around 8% faster, thanks to
        using a list comprehension for the headers, using a local variable for
        ``wfile.write``, and inlining the body writing

    *   Likewise, :func:`degu.client.write_request()` is also now around 8%
        faster, thanks to the same optimizations

    *   ``benchmark.py`` is now around 6% faster for ``AF_INET6`` and around 7%
        faster for ``AF_UNIX``

.. note::

    These benchmarks were done on an Intel® Core™ i5-4200M (2.5 GHz, dual-core,
    hyper-threaded) CPU running 64-bit Ubuntu 14.04.1, on AC power using the
    "performance" governor.

    To reproduce these results, you'll need to copy the ``benchmark.py`` and
    ``benchmark-parsing.py`` scripts from the Degu 0.9 source tree to the Degu
    0.8 source tree.



0.8 (August 2014)
-----------------

`Download Degu 0.8`_

Changes:

    * Add new :mod:`degu.rgi` module with :class:`degu.rgi.Validator` middleware
      for for verifying that servers, other middleware, and applications all
      comply with the :doc:`rgi` specification; this is a big step toward
      stabilizing both the RGI specification and the Degu API

    * Remove ``degu.server.Handler`` and ``degu.server.validate_response()``
      (unused since Degu 0.6)



0.7 (July 2014)
---------------

`Download Degu 0.7`_

Changes:

    * Rework :func:`degu.base.read_preamble()` to do header parsing itself; this
      combines the functionality of the previous ``read_preamble()`` function
      with the functionality of the now removed ``parse_headers()`` function
      (this is a breaking internal API change)

    * Add a C implementation of the new ``read_preamble()`` function, which
      provides around a 318% performance improvement over the pure-Python
      equivalent in Degu 0.6

    * The RGI server application used in the ``benchmark.py`` script now uses a
      static response body, which removes the noise from ``json.loads()``,
      ``json.dumps()``, and makes the ``benchmark.py`` results more consistent
      and more representative of true Degu performance

    * When using the new C version of ``read_preamble()``, ``benchmark.py`` is
      now around 20% faster for ``AF_INET6``, and around 26% faster for
      ``AF_UNIX`` (on an Intel® Core™ i7-4900MQ when using the *performance*
      governor); note that to verify this measurement, you need to copy the
      ``benchmark.py`` script from the Degu 0.7 tree back into the Degu 0.6 tree



0.6 (June 2014)
---------------

`Download Degu 0.6`_

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
      server-wide and per-connection information has been moved into the new
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

`Download Degu 0.5`_

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


.. _`Download Degu 0.9`: https://launchpad.net/degu/+milestone/0.9
.. _`Download Degu 0.8`: https://launchpad.net/degu/+milestone/0.8
.. _`Download Degu 0.7`: https://launchpad.net/degu/+milestone/0.7
.. _`Download Degu 0.6`: https://launchpad.net/degu/+milestone/0.6
.. _`Download Degu 0.5`: https://launchpad.net/degu/+milestone/0.5

.. _`HTTPConnection.request()`: https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection.request

