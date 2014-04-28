Tutorial
========

Let's immediately clarify where Degu is *not* a good fit:

.. warning::

    Degu is *not* meant for production web-sites, public REST APIs, nor any
    other public HTTP server reachable across the Internet.  The Degu server
    only supports a subset of HTTP 1.1 features and is likely not compatible
    with a broad range of HTTP clients.

If Degu isn't a good fit for your problem, please check out `gunicorn`_ and
`modwsgi`_.

**So where is Degu a good fit?**

Degu is a *fantastic* fit if you're implementing REST APIs for device-to-device
communication on the local network.  In particular, Degu is aimed at P2P
services that expose rich applications and even platform features over HTTP
(secured with SSL, using client certificates for authentication).

Degu is a `Python3`_ library that provides both an HTTP server and a matching
HTTP client.  In a nutshell, the typical Degu usage pattern is:

    1. Application starts an embedded :class:`degu.server.SSLServer` on a
       random, unprivileged port

    2. Application advertises this server to peers on the local network using
       `Avahi`_ or similar

    3. Peers use a :class:`degu.client.SSLClient` to make requests to this
       server for structured data sync, file transfer, RPC, or whatever else the
       application REST API might expose



Example: SSL reverse-proxy
--------------------------

Here's a minimal :doc:`rgi` application:

>>> def example_app(request):
...     return (200, 'OK', {'x-msg': 'hello, world'}, None)
...

Although not particularly useful, it's still a working example in only 2 lines
of code.

It's fun and easy to create a throw-away HTTP server on which to run our
``example_app``.  We'll create a server that only accepts connections from the
IPv4 looback device:

>>> from degu.misc import TempServer
>>> server = TempServer(('127.0.0.1', 0), None, example_app)

That just spun-up a :class:`degu.server.Server` in a new
`multiprocessing.Process`_ (which will be automatically terminated when the
:class:`degu.misc.TempServer` instance is garbage collected).

Now we'll need a :class:`degu.client.Client` so we can make requests to our
above ``server``:

>>> from degu.client import Client
>>> client = Client(server.address)
>>> conn = client.connect()
>>> conn.request('GET', '/')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

Notice that the client ``Repsonse`` namedtuple is the exact same tuple returned
by ``example_app``.  The Degu client API and the RGI application API have been
designed to complement each other.  Think of them almost like inverse functions.

For example, here's an RGI application that implements a `reverse-proxy`_:

>>> from degu.base import build_uri, make_output_from_input
>>> class ProxyApp:
...     def __init__(self, address):
...         self.client = Client(address)
... 
...     def __call__(self, request):
...         conn = self.client.connect()
...         response = conn.request(
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

This case is slightly more complicated as the RGI callable will be a
``ProxyApp`` instance rather than a plain function.  In order to avoid subtle
problems when pickling and un-pickling complex objects on their way to a new `multiprocessing.Process`_, it's best to pass only functions and simple data
structures to a new process.  This approach also avoids importing unnecessary
modules and consuming unnecessary resources in your main application process.

So in this case, it's best to specify a *build_func*:

>>> def build_proxy_app(address):
...     return ProxyApp(address)
...

It's likewise fun and easy to create throw-away SSL certificate chains, and a
throw-away HTTPS server on which to run our ``ProxyApp``.  We'll create a server
that accepts connections on any IPv6 address (but only from clients with a
client certificate signed by the correct client certificate authority):

>>> from degu.misc import TempPKI, TempSSLServer
>>> pki = TempPKI(client_pki=True)
>>> proxy_server = TempSSLServer(pki, ('::', 0, 0, 0), build_proxy_app, server.address)

That just spun-up a :class:`degu.server.SSLServer` in a new
`multiprocessing.Process`_ (which will be automatically terminated when the
:class:`degu.misc.TempSSLServer` instance is garbage collected).

Finally, we'll need a :class:`degu.client.SSLClient` so we can make requests to
our ``proxy_server``:

>>> from degu.client import SSLClient, build_client_sslctx
>>> sslctx = build_client_sslctx(pki.get_client_config())
>>> client = SSLClient(sslctx, proxy_server.address)
>>> conn = client.connect()
>>> conn.request('GET', '/')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

This example is based on real-world Degu usage.  This is more or less how
`Dmedia`_ uses Degu as an SSL front-end for `CouchDB`_ (although many details
were left out for brevity).



Trade-offs
----------

Degu is focused on:

    * **Security** - Degu is focused on security, even when at the expense of
      compatibility; the more secure Degu can be, the more we can consider
      exposing highly interesting platform features over HTTP

    * **High-throughput at low-concurrency** - being able to handle 100k
      concurrent connections doesn't necessarily mean you can keep a 10GbE local
      network saturated with just a few concurrent connections; Degu is being
      optimized for the latter, even when (possibly) at the expense of the
      former

    * **Modern SSL best-practices** - Degu is highly restrictive in how it will
      configure an `ssl.SSLContext`_; although this means being compatible with
      fewer HTTP clients, Degu is built from the assumption that you have
      control of both endpoints, and that the client is likely a
      :class:`degu.client.SSLClient` 

    * **Full IPv6 address semantics** - on both the server and client, you use
      a 4-tuple for IPv6 addresses, which gives you access to the *scopeid*
      needed for `link-local addresses`_; on the other hand, the Degu server
      doesn't support virtual hosts, SNI, or in general doing the right thing
      when the "official" hostname is a DNS name... Degu servers are expected to
      be reached be IP address alone (either an IPv6 or IPv4 address)

.. note::

    In contrast to the server, the Degu client does aim to support virtual hosts
    and SNI, and is generally compatible with at least the `Apache 2.4`_ and
    `CouchDB`_ servers.



.. _`gunicorn`: http://gunicorn.org/
.. _`modwsgi`: https://code.google.com/p/modwsgi/
.. _`Python3`: http://docs.python.org/3/
.. _`Avahi`: http://avahi.org/
.. _`multiprocessing.Process`: http://docs.python.org/3/library/multiprocessing.html#the-process-class
.. _`http.client`: http://docs.python.org/3/library/http.client.html
.. _`Dmedia`: https://launchpad.net/dmedia
.. _`CouchDB`: http://couchdb.apache.org/
.. _`Apache 2.4`: http://httpd.apache.org/docs/2.4/
.. _`reverse-proxy`: http://en.wikipedia.org/wiki/Reverse_proxy
.. _`ssl.SSLContext`: http://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
