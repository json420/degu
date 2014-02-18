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
    library.  In fact, the only client Degu is currently *guaranteed* to be
    compatible with is :mod:`degu.client`, its internal HTTP client library.

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

>>> from degu.client import Client
>>> client = Client(server.address)
>>> client.request('GET', '/')
Response(status=200, reason='OK', headers={'hello': 'world'}, body=None)

Not bad for 7 lines of code, but we're just getting started!

Notice that the client ``Repsonse`` namedtuple is the exact same tuple returned
by ``useless_app()``.  The Degu client API and the RGI application API have
been designed to complement each other.  Think of them almost like inverse
functions.

For example, here's an RGI application that implements a `reverse-proxy`_:

>>> from degu.base import build_uri, make_output_from_input
>>> import threading
>>> class ProxyApp:
...     def __init__(self, address):
...         self.address = address
...         self.threadlocal = threading.local()
... 
...     def get_client(self):
...         if not hasattr(self.threadlocal, 'client'):
...             self.threadlocal.client = Client(self.address)
...         return self.threadlocal.client
... 
...     def __call__(self, request):
...         client = self.get_client()
...         response = client.request(
...             request['method'],
...             build_uri(request['path'], request['query']),
...             request['headers'],
...             make_output_from_input(request['body'])
...         )
...         return (
...             response.status,
...             response.reason,
...             response.headers,
...             make_output_from_input(response.body)
...         )
...

It's likewise fun and easy to create an *additional* throw-away HTTP server on
which to run this ``ProxyApp``.

However, this case is slightly more complicated as the RGI callable will be a
``ProxyApp`` instance rather than a plain function.  So this time we'll need to
specify a *build_func*:

>>> def build_proxy_app(address):
...     return ProxyApp(address)
...

In order to avoid subtle problems when pickling and un-pickling complex objects
on their way to a new ``multiprocessing.Process``, it's best to pass only
functions and simple data structures to a new process (although this isn't a
strict requirement).

Anyway, for even more fun, we'll bind this 2nd HTTP server to the IPv6 loopback
address:

>>> proxy_server = TempServer(('::1', 0, 0, 0), build_proxy_app, server.address)

Finally, we'll need a suitable :class:`degu.client.Client` so we can make
requests to our ``proxy_server``:

>>> proxy_client = Client(proxy_server.address)
>>> proxy_client.request('GET', '/')
Response(status=200, reason='OK', headers={'hello': 'world'}, body=None)

Not bad for 41 lines of code!



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
      Degu is being designed for the latter, even at the expense of the former

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
