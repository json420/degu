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

>>> def example_app(session, request):
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
will use the :func:`degu.util.relative_uri()` helper function:

>>> from degu.util import relative_uri
>>> class ProxyApp:
...     def __init__(self, address):
...         self.client = Client(address)
... 
...     def __call__(self, session, request):
...         if '__conn' not in session:
...             session['__conn'] = self.client.connect()
...         conn = session['__conn']
...         return conn.request(
...             request['method'],
...             relative_uri(request),
...             request['headers'],
...             request['body']
...         )
...

The important thing to note above is that Degu server applications can
*directly* use the incoming HTTP request body object in their forwarded HTTP
client request, and can likewise return the *entire* HTTP response object from
the upstream server.  (This in new in Degu 0.6, whereas previous versions
required you to wrap the HTTP body in both directions using the defunct
``make_output_from_input()`` function).

For this reason, the 4-tuple response object is something you'll really want to
commit to memory, as it is used both server-side and client-side::

    (status, reason, headers, body)

Anyway, this case is slightly more complicated as the RGI callable will be a
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



Request & response bodies
-------------------------

As exciting as our first two examples were, you may have noticed that no request
or response bodies were used.

The reason is because this is a broad and complex topic in Degu, especially as
Degu fully exposes HTTP chunked transfer-encoding semantics.

However, for your essential survival guide, you only need to know three things:

    1. Degu uses ``None`` to represent the absence of an HTTP body

    2. When you receive an HTTP body, it will always have a ``read()`` method
       you can use to retrieve its contents

    3. When you send an HTTP body, you can always send a ``bytes`` instance

Before we dive into the details, here's a quick example:

>>> def hello_response_body(session, request):
...     return (200, 'OK', {}, b'hello, world')
...
>>> server = TempServer(('127.0.0.1', 0), None, hello_response_body)
>>> client = Client(server.address)
>>> conn = client.connect()
>>> response = conn.request('GET', '/')

Notice that this time the response body is a :class:`degu.base.Body` instance,
rather than ``None``:

>>> response.body
Body(<rfile>, 12)

The ``body.chunked`` attribute will be ``True`` when the body uses chunked
transfer-encoding, and will be ``False`` when the body has a content-length:

>>> response.body.chunked
False

As this body is not chunk-encoded, it has a ``content_length`` attribute, which
will match the content-length in the response headers:

>>> response.body.content_length
12
>>> response.headers
{'content-length': 12}

Finally, we can use the ``body.read()`` method to read its content:

>>> response.body.read()
b'hello, world'
>>> conn.close()
>>> server.terminate()


IO abstractions
---------------

On both the client and server ends, Degu uses the same set of shared IO
abstractions to represent HTTP request and response bodies.

As the IO *directions* of the request and response are flipped depending on
whether you're looking at things from a client vs server perspective, it's
helpful to think in terms HTTP *input* bodies and HTTP *output* bodies.

An **HTTP input body** will always be one of three types:

    * ``None`` --- meaning no HTTP input body

    * :class:`degu.base.Body` --- an HTTP input body with a content-length

    * :class:`degu.base.ChunkedBody` --- an HTTP input body that uses chunked
      transfer-encoding

From the client perspective, our input is the HTTP response body received from
the server.

From the server perspective, our input is the HTTP request body received from
the client.

When the HTTP input body is not ``None``, the receiving endpoint is responsible
for reading the entire input body, which must be completed before the another
request/response sequence can be initiated using that same connection.

Your **HTTP output body** can be:

    ==================================  ========  ================
    Type                                Encoding  Source object
    ==================================  ========  ================
    ``None``                            *n/a*     *n/a*
    ``bytes``                           Length    *n/a*
    ``bytearray``                       Length    *n/a*
    :class:`degu.base.Body`             Length    File-like object
    :class:`degu.base.BodyIter`         Length    An iterable
    :class:`degu.base.ChunkedBody`      Chunked   File-like object
    :class:`degu.base.ChunkedBodyIter`  Chunked   An iterable
    ==================================  ========  ================

From the client perspective, our output is the HTTP request body sent to the
server.

From the server perspective, our output is the HTTP response body sent to the
client.

The sending endpoint doesn't directly write the output, but instead only
*specifies* the output to be written, after which the client or server library
internally handles the writing.

**Server agnostic** RGI applications are generally possible.

These four IO abstraction classes are exposed in the RGI *session* argument
(similar to the WSGI ``environ['wsgi.file_wrapper']``):

    ==================================  =====================================
    Exposed via                         Degu implementation
    ==================================  =====================================
    ``session['rgi.Body']``             :class:`degu.base.Body`
    ``session['rgi.BodyIter']``         :class:`degu.base.BodyIter`
    ``session['rgi.ChunkedBody']``      :class:`degu.base.ChunkedBody`
    ``session['rgi.ChunkedBodyIter']``  :class:`degu.base.ChunkedBodyIter`
    ==================================  =====================================

If server applications only use these wrapper classes via the *session* argument
(rather than directly importing them from :mod:`degu.base`), they are kept
abstracted from Degu as an implementation, and could potentially run on other
HTTP servers implemented the :doc:`rgi`.

The place where this breaks down a bit is with something like our SSL
reverse-proxy example.  Were you using the Degu client but not running on the
Degu server, you couldn't *directly* use the incoming HTTP request body in your
forwarded client request.  Likewise, you couldn't *directly* use the response
body from the upstream HTTP server in your application response.

In both directions, these HTTP input bodies would need to be wrapped in a
``session['rgi.Body']`` or ``session['rgi.ChunkedBody']`` instance as
appropriate (but no wrapping is needed when the HTTP body is ``None``).



Example: chunked encoding
-------------------------

For our final example, we'll show how chunked transfer-encoding is fully exposed
in Degu.

For good measure, we'll toss in HTTP bodies with a content-length, just to
compare and contrast.

We'll also demonstrate how to use the :class:`degu.base.BodyIter` and
:class:`degu.base.ChunkedBodyIter` classes to produce your HTTP output body,
both for the server response body and the client request body.

First, we'll define two Python generator functions to product the server
response body, one for chunked transfer-encoding, and another for 
content-length encoding:

>>> def chunked_response_body(echo):
...     yield (echo, None)
...     yield (b' ', None)
...     yield (b'are', None)
...     yield (b' ', None)
...     yield (b'belong', ('extra', 'special'))
...     yield (b' ', None)
...     yield (b'to', None)
...     yield (b' ', None)
...     yield (b'us', None)
...     yield (b'', None)
...
>>> def response_body(echo):
...     yield echo
...     yield b' '
...     yield b'are'
...     yield b' '
...     yield b'belong'
...     yield b' '
...     yield b'to'
...     yield b' '
...     yield b'us'
... 
>>> len(b''.join(response_body(b''))) == 17  # 17 used below
True

Second, we'll define an RGI application that will return a response body using
chunked transfer encoding if we ``POST /chunked``, and will return a body with
a content-length if we ``POST /length``:

>>> def rgi_io_app(session, request):
...     if len(request['path']) != 1 or request['path'][0] not in ('chunked', 'length'):
...         return (404, 'Not Found', {}, None)
...     if request['method'] != 'POST':
...         return (405, 'Method Not Allowed', {}, None)
...     if request['body'] is None:
...         return (400, 'Bad Request', {}, None)
...     echo = request['body'].read()  # Body/ChunkedBody agnostic
...     if request['path'][0] == 'chunked':
...         body = session['rgi.ChunkedBodyIter'](chunked_response_body(echo))
...     else:
...         body = session['rgi.BodyIter'](response_body(echo), len(echo) + 17)
...     return (200, 'OK', {}, body)
... 

As usual, we'll start a throw-away server and create a client:

>>> server = TempServer(('127.0.0.1', 0), None, rgi_io_app)
>>> client = Client(server.address)

For now we'll just use a simple ``bytes`` instance for the client request body.
For example, if we ``POST /chunked``:

>>> conn = client.connect()
>>> response = conn.request('POST', '/chunked', {}, b'All your base')

Notice that a :class:`degu.base.ChunkedBody` is returned:

>>> response.body.chunked
True
>>> response.body
ChunkedBody(<rfile>)
>>> response.headers
{'transfer-encoding': 'chunked'}

We can easily iterate through the ``(data, extension)`` tuples for each chunk
in the chunk encoded response like this:

>>> for (data, extension) in response.body:
...     print((data, extension))
...
(b'All your base', None)
(b' ', None)
(b'are', None)
(b' ', None)
(b'belong', ('extra', 'special'))
(b' ', None)
(b'to', None)
(b' ', None)
(b'us', None)
(b'', None)

(Note that :meth:`degu.base.ChunkedBody.readchunk()` can also be used to
manually step through the chunks.)

:meth:`degu.base.ChunkedBody.read()` can be used to accumulate all the chunk
data into a single ``bytearray``, at the expense of loosing the exact chunk data
boundaries and any chunk extensions:

>>> response = conn.request('POST', '/chunked', {}, b'All your base')
>>> response.body.read()
bytearray(b'All your base are belong to us')

API-wise, ``body.read()`` can always be used without worrying about the
transfer-encoding, but in real applications you should be very cautions about
this do the possibility of unbounded memory usage with chunked
transfer-encoding.

But at least for illustration, note that :meth:`degu.base.ChunkedBody.read()`
is basically equivalent to :meth:`degu.base.Body.read()`.

For example, if we ``POST /length``:

>>> response = conn.request('POST', '/length', {}, b'All your base')

Notice that the response body is a :class:`degu.base.Body` instance:

>>> response.body.chunked
False
>>> response.body
Body(<rfile>, 30)
>>> response.headers
{'content-length': 30}

And that we get the expected result from ``body.read()``:

>>> response.body.read()
b'All your base are belong to us'

For one last bit of fancy, you can likewise use an arbitrary iterable to
generate your HTTP client request body.  Let's define a Python generator to be
used with chunked-transfer encoding:

>>> def chunked_request_body():
...     yield (b'All',        None)
...     yield (b' ',          None)
...     yield (b'your',       None)
...     yield (b' ',          None)
...     yield (b'*something', None)
...     yield (b' ',          ('key', 'value'))
...     yield (b'else*',      ('chunk', 'extensions'))
...     yield (b'',           ('are', 'neat'))
...

To use this generator as our request body, we need to wrap it in a
:class:`degu.base.ChunkedBodyIter`, like this:

>>> from degu.base import ChunkedBodyIter
>>> body = ChunkedBodyIter(chunked_request_body())

And then if we ``POST /chunked``:

>>> response = conn.request('POST', '/chunked', {}, body)
>>> response.body.read()
bytearray(b'All your *something else* are belong to us')

Or if we ``POST /length``:

>>> body = ChunkedBodyIter(chunked_request_body())
>>> response = conn.request('POST', '/length', {}, body)
>>> response.body.read()
b'All your *something else* are belong to us'

Well, that's all the time for fancy we have now:

>>> conn.close()
>>> server.terminate()



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



HTTP/1.1 subset
---------------

For simplicity, performance, and especially security, the Degu server and client
support only a rather idealized subset of `HTTP/1.1`_ features.

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
