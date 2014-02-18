Tutorial
========

Before "Shinny new web server for Python3!" lust-O-vision carries you too far
along, let's immediately clarify where Degu is *not* a good fit, because chances
are, these aren't the "python3 web server" you're looking for.

.. warning::

    Degu is *not* meant for production web-sites, public REST APIs, nor any
    other public HTTP server reachable across the Internet.  To whatever extent
    Degu might seem usable as a production Internet server (or a even
    high-traffic *Intranet* server), this will be purely by coincidence and is
    not something you should count on going forward!

If Degu isn't a good fit for your problem, please check out `gunicorn`_ and
`modwsgi`_, two excellent ways to get your Python3 + HTTP server fix.

.. warning::

    Also, no promises that the Degu server will be compatible with your favorite
    browser, your favorite embedded WebKit, nor your favorite HTTP client
    library.  In fact, the only client Degu is *guaranteed* to be compatible
    with is *itself* (via :mod:`degu.client`, its internal HTTP client library)

So, yeah, also that.  Note that when it comes to this 2nd warning, the Novacut
team is happy to accept patches and suggestions needed for the Degu server to
work well with *most* any *well-behaved* HTTP client, as long as such changes
don't reduce our warm-fuzzy security feelings or otherwise compromise where we
need Degu to be stunning.

When the Degu server isn't compatible with a specific HTTP client, it's likely
just a lack of knowledge on our part, although perhaps not always.  For what
it's worth, we have extensive unit tests currently running that work with the
`CouchDB`_ replicator as a client, and we've also tested quite a bit using
Python's `http.client`_, although that's not in our current unit tests
(something we should fix).

Likewise, there's no reason the Degu client shouldn't work with a wide-range of
well-behaved HTTP servers.  We know the Degu client works well with the
`CouchDB`_ server (from both from painfully extensive unit tests and our use in
production), and works well with `Apache 2.4`_ (via our use in production).

However, be warned that the outlook is grim if you hope we'll budge on that
1st warning.  There are many excellent existing servers that allow you to run
Python-powered websites, including on a number of excellent Python-powered web
servers.  But there are fundamentally opposing reason why we couldn't use those
existing servers for the embedded Dmedia/Novacut server, and why Degu is weak
where those existing servers are strong, yet Degu is strong where those existing
servers are weak.

Before we get into the details of where Degu excels and why, please whet your
appetite with some code!



READY! SET! GO!
---------------

This is an utterly minimal :doc:`rgi` application:

>>> def useless_app(request):
...     return (200, 'OK', {'hello': 'world'}, None)
...

Sure, it's *also* completely useless, but still a working example in 2 lines of
code.

It's fun and easy to create a throw-away HTTP server on which to run our
``useless_app()``:

>>> from degu.misc import TempServer
>>> server = TempServer(('127.0.0.1', 0), None, useless_app)

That just spun-up a :class:`degu.server.Server` in a new
``multiprocessing.Process`` (which, BTW, will be automatically terminated when the :class:`degu.misc.TempServer` instance is garbage collected).

Now we'll need a :class:`degu.client.Client` so we can make requests to our
above ``server``:

>>> client = server.get_client()
>>> client.request('GET', '/')
Response(status=200, reason='OK', headers={'hello': 'world'}, body=None)
>>> client.close()

Not bad for 8 lines of code, but we're just getting started!

Notice that the client ``Repsonse`` namedtuple is the exact same tuple returned
by ``useless_app()``.  The Degu client API carefully complements the RGI
application API.  Think of them almost like inverse functions.

Moving on up, this is a :doc:`rgi` application that implements a surprisingly
complete and useful `reverse-proxy`_:

>>> from degu.base import build_uri, make_output_from_input
>>> class ProxyApp:
...     def __init__(self, client):
...         self.client = client
... 
...     def __call__(self, request):
...         response = self.client.request(
...             request['method'],
...             build_uri(request['path'], request['query']),
...             request['headers'],
...             make_output_from_input(request['body']),
...         )
...         return (
...             response.status,
...             response.reason,
...             response.headers,
...             make_output_from_input(response.body),
...         )
...

It's likewise fun and easy to create an *additional* throw-away HTTP server on
which to run this ``ProxyApp``.

However, this case is slightly more complicated as the RGI callable will be a
``ProxyApp`` instance rather than a simple function.  So this time we'll need to
specify a *build_func*:

>>> def build_proxy_app(address):
...     from degu.client import Client
...     client = Client(address)
...     return ProxyApp(client)
...

Previously we passed a *build_func* of ``None`` in order to specify the default
*build_func*, which takes a single argument, our ``useless_app()`` simple
function (or any other simple function to be used as the RGI callable).

In order to avoid subtle problems with pickling and un-pickling complex objects
on their way to a new ``multiprocessing.Process``, the Degu API encourages us
to pass only simple functions and simple data structures to a new process.  A
good rule of thumb is to pass only JSON-serializable data structures, plus
simple functions.

.. note::

    When is a function not "simple"?  We consider any dyed-in-the-wool Python
    function (aka, not a method, not a callable instance) to be a "simple
    function".  But the place to be careful is with decorators, which might
    return your same simple function merely with a special attribute assigned,
    but could likewise return a new class instance with your simple function as
    an instance attribute, all depending on the decorator in question.

    Degu itself doesn't do any hard enforcement of this either way, but Degu
    does try to provide an API that makes the "right" thing feel like the
    "natural" thing (even if it might funnel you toward the *correct*
    destination with a lot of friendly road cones).

Looked at another way, the Degu API encourages us *not* to import unnecessary
modules in our application's main process, and *not* to create unnecessary
resources in our main process (especially resources that will never be used in
said main process).

Which all might seem a bit odd, but remember, Degu is meant to be embedded in
desktop and mobile applications.  During a given application's process lifetime,
it might never need to start its embedded Degu server.  So please don't make
that process's memory footprint needlessly larger!

For example, thus far we haven't directly imported :mod:`degu.client`, which you
can see ``build_proxy_app()`` lazily imports in its function scope.  The new
process just needs to be passed an *address* tuple, not an actual
:class:`degu.client.Client` instance.

Anyway, for even more fun, we'll bind this 2nd HTTP server to the IPv6 loopback
address:

>>> proxy_server = TempServer(('::1', 0, 0, 0), build_proxy_app, client.address)

As before, we'll need a suitable :class:`degu.client.Client` so we can make
requests to our ``proxy_server``:

>>> proxy_client = proxy_server.get_client()
>>> proxy_client.request('GET', '/')
Response(status=200, reason='OK', headers={'hello': 'world'}, body=None)
>>> proxy_client.close()

In these mere 36 lines, we:

    * Defined a simple (though useless) RGI app
    * Created a destination server running the above app
    * Created an HTTP client that can connect to the above server
    * Defined a darn near complete reverse-proxy RGI app
    * Created a 2nd server running the above reverse-proxy app
    * Created a 2nd client that can connect to the above proxy server
    * Made a request to the proxy server, onto the destination server, with a
      response moving all the way back up to out outer proxy client

Good enough for government work, and then some!



Where Degu excels
-----------------

Degu is a *fantastic* fit if you're implementing REST APIs for device-to-device
communication on the local network, and in particular if your implementing
symmetric, P2P communication in order to expose rich applications features and
deep platform integration over HTTP.

Degu is being designed for:

    * Security, even at the expense of compatibility - the more secure Degu can
      be, the more we can consider exposing highly interesting platform features
      over HTTP

    * High-throughput at low-concurrency - being able to handle a million
      concurrent connections without crashing (and without running out of
      memory) is a much different problem than trying to keep a 10 gigabit
      local Ethernet connection fully saturated with just a few connections;
      Degu is being designed for the later, even at the expense of the former

    * Modern SSL best-practices, with client cert authentication - one of the
      big advantages of not trying to be compatible with browsers is we can push
      the limit when it comes to secure but user-friendly security, privacy, and
      authentication.



.. _`gunicorn`: http://gunicorn.org/
.. _`modwsgi`: https://code.google.com/p/modwsgi/
.. _`http.client`: http://docs.python.org/3/library/http.client.html
.. _`CouchDB`: http://couchdb.apache.org/
.. _`Apache 2.4`: http://httpd.apache.org/docs/2.4/
.. _`reverse-proxy`: http://en.wikipedia.org/wiki/Reverse_proxy
