Tutorial
========

Let's immediately clarify where Degu is *not* a good fit:

.. warning::

    Degu is *not* meant for production web-sites, public REST APIs, nor any
    other public HTTP server reachable across the Internet.  The Degu server
    only supports a subset of HTTP/1.1 features and is likely not compatible
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

>>> def example_app(connection, request):
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

Now we'll need a :class:`degu.client.Client` so we can make connections to our
above ``server``:

>>> from degu.client import Client
>>> client = Client(server.address)

A :class:`degu.client.Client` is stateless and thread-safe, and does not itself
reference any socket resources.  In order to make requests, we'll need to
create a :class:`degu.client.Connection`, with with we can make one or more
requests:

>>> conn = client.connect()
>>> conn.request('GET', '/')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

In contrast to the client, a :class:`degu.client.Connection` is statefull and is
*not* thread-safe.

As both the Degu client and server are built for HTTP/1.1 only, connection
reuse is assumed.  We can make another request to our ``server`` using the same
connection:

>>> conn.request('PUT', '/foo')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

After you're done using a connection, it's a good idea to explicitly close it,
although note that a connection is also automatically closed when garbage
collected.

Close the connection like this:

>>> conn.close()

Notice that the :class:`degu.client.Response` namedtuple returned above is the
exact same tuple returned by our ``example_app``.  The Degu client API and the
RGI application API have been carefully designed to complement each other.
Think of them almost like inverse functions.

For example, here's an RGI application that implements a `reverse-proxy`_, which
will use the :func:`degu.util.relative_uri()` and
:func:`degu.util.output_from_input()` functions:

>>> from degu.util import relative_uri, output_from_input
>>> class ProxyApp:
...     def __init__(self, address):
...         self.client = Client(address)
... 
...     def __call__(self, connection, request):
...         if '__conn' not in connection:
...             connection['__conn'] = self.client.connect()
...         conn = connection['__conn']
...         response = conn.request(
...             request['method'],
...             relative_uri(request),
...             request['headers'],
...             output_from_input(connection, request['body'])
...         )
...         return (
...             response.status,
...             response.reason,
...             response.headers,
...             output_from_input(connection, response.body)
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
>>> pki = TempPKI()
>>> proxy_server = TempSSLServer(
...     pki.get_server_config(), ('::', 0, 0, 0), build_proxy_app, server.address
... )
... 

That just spun-up a :class:`degu.server.SSLServer` in a new
`multiprocessing.Process`_ (which will be automatically terminated when the
:class:`degu.misc.TempSSLServer` instance is garbage collected).

Finally, we'll need a :class:`degu.client.SSLClient` so we can make requests to
our ``proxy_server``:

>>> from degu.client import SSLClient, build_client_sslctx
>>> sslctx = build_client_sslctx(pki.get_client_config())
>>> proxy_client = SSLClient(sslctx, proxy_server.address)
>>> proxy_conn = proxy_client.connect()
>>> proxy_conn.request('GET', '/')
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



Example: HTTP over AF_UNIX
--------------------------

A highly differentiating feature of Degu is that both its server and client can
*transparently* do HTTP over ``AF_UNIX``.

When creating a server or client, the *address* argument itself conveys
everything needed in order to do HTTP over ``AF_INET``, ``AF_INET6``, or
``AF_UNIX``.  This way 3rd-party application software can pass around the single
*address* argument, all while remaining gleefully unaware of what the underlying
socket family will be.

For example, when creating a server, if your *address* is an ``str``, then it
must be the absolute, normalized path of a socket file that does *not* yet
exist:

>>> import tempfile
>>> from os import path
>>> tmpdir = tempfile.mkdtemp()
>>> address = path.join(tmpdir, 'my.socket')

We'll then create a :class:`degu.server.Server`, which in this case we'll again
do via creating a :class:`degu.misc.TempServer` instance:

>>> from degu.misc import TempServer
>>> server = TempServer(address, None, example_app)

Even though in this case the *address* we provide when creating a client will
match the *address* we provided when creating a server, note that this wont
always be true, depending on the exact *address* type and value.  You should
always create a client using the resulting :attr:`degu.server.Server.address`
attribute.

So as in our previous example, we'll create a :class:`degu.client.Client` like
this:

>>> from degu.client import Client
>>> client = Client(server.address)

And then, as in our previous example, wa can create a
:class:`degu.client.Connection` and make a request like this:

>>> conn = client.connect()
>>> conn = client.connect()
>>> conn.request('GET', '/')
Response(status=200, reason='OK', headers={'x-msg': 'hello, world'}, body=None)

The important point is that both the Degu server and client keep 3rd-party
applications highly abstracted from what the underlying socket family will be
for a given *address*, thereby backing up our claim that Degu can
*transparently* do HTTP over ``AF_UNIX``.

This is especially critical for `Novacut`_, which is built as a set of
network-transparent services, most of which will usually all be running on the
local host, but any of which could likewise be running on a remote host.

For more details, see the documentation for the :mod:`degu.server` and
:mod:`degu.client` modules.



HTTP/1.1 subset
---------------

For simplicity, performance, and especially security, the Degu server and client
support only a subset of `HTTP/1.1`_ features.

Although the Degu server and client *generally* operate in an HTTP/1.1
compliant fashion themselves, they do *not* support all valid HTTP/1.1 features
and permutations from the other endpoint.  However, the unsupported features are
seldom used by other modern HTTP/1.1 servers and clients, so these restrictions
don't particularly limit the servers and clients with which Degu can interact.

Also, remember that Degu is primarily aimed at highly specialized P2P usage
where Degu clients will only be talking to the Degu servers running on other
devices on the same local network.  Degu is also aimed at using HTTP as a
network-transparent RPC mechanism, including when communicating with servers
running on the same host using HTTP over ``AF_UNIX``.

In particular, Degu is restrictive when it comes to:

**HTTP protocol version:**

    * Degu currently only supports HTTP/1.1 clients and servers; although in the
      future Degu may support, say, the finalized HTTP/2.0 protocol, there is no
      plan for Degu ever to support HTTP/1.0 (or older) clients and servers

**HTTP headers:**

    * Although allowed by HTTP/1.1, Degu doesn't support multiple occurrences of
      the same header

    * Although allowed by HTTP/1.1, Degu doesn't support headers whose value
      spans multiple lines in the request or response preamble

    * Although allowed by HTTP/1.1, Degu doesn't allow both a Content-Length and
      a Transfer-Encoding header to be present in the same request or response
      preamble

    * Degu is less forgiving when it comes to white-space in the Header lines,
      which must always have the form::

        'Name: Value\r\n'

    * Although Degu accepts mixed case header names from the other endpoint, the
      Degu server and client always case-fold (lowercase) the header names prior
      to passing control to 3rd-party RGI server application software

    * Degu :doc:`rgi` server applications must only include case-folded header
      names in their response tuple, and likewise, 3rd-party application
      software must only include case-folded header names when calling
      :meth:`degu.client.Connection.request()`

    * The Degu server includes *zero* headers by default, although :doc:`rgi`
      server applications are free to include whatever headers they see fit in
      their response; of particular note, the Degu server doesn't by default
      include a ``'date'`` header

    * The Degu client includes *zero* headers by default, although 3rd-party
      applications are free to include whatever headers they see fit in their
      request; of particular note, the Degu client doesn't by default include a
      ``'host'`` header

    * A strait-forward way to minimize the overhead of the HTTP protocol is to
      simply send fewer request and response headers; both the Degu server and
      client aggressively peruse this optimization route, even at the expense of
      of operating in a strictly HTTP/1.1 compliant fashion (again, 3rd-party
      applications are free to include additional headers as needed)

**HTTP request method:**

    * Currently the Degu server and client only allow the request method to be
      ``'GET'``, ``'HEAD'``, ``'DELETE``, ``'PUT'``, or ``'POST'``; in
      particular this restriction is in place out of security consideration when
      the Degu is used as a reverse proxy to something like `CouchDB`_; if this
      is too restrictive for your application, please `file a bug`_ and we'll
      consider relaxing this somewhat

**HTTP request body:**

    * A request body is only allowed when the request method is ``'PUT'`` or
      ``'POST'``

    * A request body is *not* allowed when the request method is ``'GET'``,
      ``'HEAD'``, or ``'DELETE'``, and as such, neither a Content-Length nor a
      Transfer-Encoding header should be preset in such requests



.. _`gunicorn`: http://gunicorn.org/
.. _`modwsgi`: https://code.google.com/p/modwsgi/
.. _`Python3`: https://docs.python.org/3/
.. _`Avahi`: http://avahi.org/
.. _`multiprocessing.Process`: https://docs.python.org/3/library/multiprocessing.html#the-process-class
.. _`http.client`: https://docs.python.org/3/library/http.client.html
.. _`Dmedia`: https://launchpad.net/dmedia
.. _`CouchDB`: http://couchdb.apache.org/
.. _`Apache 2.4`: http://httpd.apache.org/docs/2.4/
.. _`reverse-proxy`: http://en.wikipedia.org/wiki/Reverse_proxy
.. _`ssl.SSLContext`: https://docs.python.org/3/library/ssl.html#ssl-contexts
.. _`link-local addresses`: http://en.wikipedia.org/wiki/Link-local_address#IPv6
.. _`HTTP/1.1`: https://www.ietf.org/rfc/rfc2616.txt
.. _`file a bug`: https://bugs.launchpad.net/degu
.. _`Novacut`: https://launchpad.net/novacut
