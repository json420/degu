REST Gateway Interface
======================

Note that this design is done out of deep respect for the `WSGI`_ standard.
Considering the delicate balance needed for backward compatibility on multiple
fronts, WSGI is an exceedingly good design.

*RGI* (REST Gateway Interface) is largely a thought experiment in what you could
do with something WSGI-like assuming you didn't need `CGI`_ compatibility, and
likewise didn't need to be compatible with any existing HTTP servers.

RGI focuses on improvement in a number of areas:

    1. It's very useful to expose connection-level semantics to sever
       applications, in addition to request-level semantics

    2. Assuming you can drop CGI compatibility, the naming conventions in the
       WSGI *environ* leave much to be desired in terms of signal-to-noise ratio

    3. ``start_response()`` is the bane of middleware components because
       if they need to inspect or to modify the response status or response
       headers, they cannot simply pass to a WSGI application the same
       ``start_response()`` callable they received from the server

    4. A reverse proxy (aka gateway) application is a good model for the needs
       of middleware; in particular, we should not require middleware components
       to re-parse or otherwise transform any values in order to do something
       meaningful with these value (eg, a reverse proxy generally needs to use
       the full request headers in its own HTTP client request)

    5. WSGI is somewhat ambiguous about Transfer-Encoding vs Content-Length,
       especially in the request body, but only in the response body; RGI aims
       to eliminate this ambiguity, and to do so in a way that allows proxy
       applications to preserve these request and response body semantics



Application callables
---------------------

RGI applications must provide a callable object to handle requests (equivalent
to the WSGI *application* callable).

However, if this application object itself has a callable ``on_connection``
attribute, this is called whenever a new connection is received, before any
requests are handled for that connection.

Most server application interfaces (like WSGI and CGI) only offer request-level
semantics, but don't offer any connection-level semantics, don't offer a way
for application to do anything special when a new connection is first received
or a way for applications to easily maintain per-connection state.

This was motivated by the somewhat specialized way in which `Dmedia`_ uses SSL,
where *authentication* is done per-connection, and only *authorization* is done
per-request.  This allows Dmedia to do extended per-connection authentication,
in particular to verify the intrinsic machine and user identities behind the
connection, based on the SSL certificate and SSL certificate authority under
which the connection was made, respectively.

This is best illustrated through an example middleware application:

>>> class Middleware:
...     def __init__(self, app):
...         self.app = app
...         if callable(getattr(app, 'on_connection', None)):
...             self._on_connection = app.on_connection
...         else:
...             self._on_connection = None
... 
...     def __call__(self, connection, request):
...         return self.app(connection, request)
... 
...     def on_connection(self, sock, connection):
...         if self._on_connection is None:
...             return True
...         return self._on_connection(sock, connection)
... 

When an application has an ``on_connection()`` callable, it must return ``True``
in order for the connection to be accepted.  If ``on_connection()`` does not
return ``True``, or if any unhandled exception is raised, the connection will be
rejected without any further processing, before any requests are handled.



Handling connections
--------------------

If an RGI application has a callable ``on_connection`` attribute, it will be
passed two arguments when handling connections: a *sock* and a *connection*.

The *sock* will be either a ``socket.socket`` instance or an ``ssl.SSLSocket``
instance.

The *connection* will be a ``dict`` containing the per-connection environment
already created by the server, which will be a subset of the equivalent
information in the WSGI *environ*.  Importantly, ``on_connection()`` is called
before any requests have been handled, and the *connection* argument will not
contain any request related information.

The *connection* argument will look something like this::

    connection = {
        'scheme': 'https',
        'protocol': 'HTTP/1.1',
        'server': ('0.0.0.0', 12345),
        'client': ('192.168.0.17', 23456),
        'ssl_compression': None,
        'ssl_cipher': ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256),
    }

When needed, the ``on_connection()`` callable can add additional information to
the *connection* ``dict``, and this same connection ``dict`` instance will be
passed to the main ``application.__call__()`` method when handling each request
within the lifetime of that connection.

In order to avoid conflicts with additional *connection* information that may be
added by future RGI servers, there is a simple, pythonic name-spacing rule: the
``on_connection()`` callable should only add keys whose name starts with
``'_'`` (underscore).

For example:

>>> class MyApp:
...     def __call__(self, connection, request):
...         return (200, 'OK', {'content-length': 12}, b'hello, world')
... 
...     def on_connection(self, sock, connection):
...         assert isinstance(sock, ssl.SSLSocket)  # Require SSL
...         connection['_user'] = 'foo'
...         connection['_machine'] = 'bar'
...         return True
...



Handling requests
-----------------

RGI applications take two arguments when handling requests: a *connection* and
a *request*.

Both are ``dict`` instances that together provide the equivalent of the WSGI
*environ* argument (note that there is no RGI equivalent of the WSGI
``start_response()`` callable).

The difference is that the *connection* argument contains only per-connection
information, and the *request* argument contains only per-request information. 
Additionally, applications can use the *connection* argument to store persistent
per-connection state (for example, a database connection or a connection to an
upstream HTTP servers in the case of a reverse proxy application).

As noted above, the *connection* argument will look something like this::

    connection = {
        'scheme': 'https',
        'protocol': 'HTTP/1.1',
        'server': ('0.0.0.0', 12345),
        'client': ('192.168.0.17', 23456),
        'ssl_compression': None,
        'ssl_cipher': ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1/SSLv3', 256),
    }

When needed, the RGI request handler callable can add additionally information
to the *connection* ``dict``, and this same connection ``dict`` instance will
be persistent throughout all request handled during the connection's lifetime.

In order to avoid conflicts with additional *connection* information that may be
added by future RGI servers, and to avoid conflicts with information added by a
possible ``on_connection()`` handler, there is a simple, pythonic name-spacing
rule: the request handler should only add keys whose name starts with ``'__'``
(double underscore).

On the other hand, the *request* argument will look something like this::

    request = {
        'method': 'POST',
        'script': ['foo'],
        'path': ['bar', 'baz'],
        'query': 'stuff=junk',
        'body': Input(rfile, 1776),  # Explained below
        'headers': {
            'accept': 'application/json',
            'content-length': 1776,
            'content-type': 'application/json',
        },
    }

As RGI does not aim for CGI compatibility, it uses shorter, lowercase keys,
(eg, ``'method'`` instead of ``'REQUEST_METHOD'``).  Also note that the
``'script'`` and ``'path'`` values are lists rather than strings.  This avoids
complicated (and error prone) re-parsing to shift the path, or to otherwise
interpret the path.

Importantly, the request headers are in a sub-dictionary.  The header names
are casefolded using ``str.casefold()``.  If the request includes a
``'content-length'``, the value is converted into a ``int`` by the server.  The 
``'headers'`` sub-dictionary is designed to be directly usable by a proxy
application when making its HTTP client request.

For example:

>>> class MyProxyApp:
...     def __init__(self, client):
...         self.client = client
... 
...     def __call__(self, connection, request):
...         if '__conn' not in connection:
...             connection['__conn'] = self.client.connect()
...         conn = connection['__conn']
...         return conn.request(server_request_to_client_request(request))
... 

An RGI application must return a ``(status, reason, headers, body)`` response
tuple, for example::

    response = (200, 'OK', {'content-length': 12}, b'hello, world')

RGI doesn't use anything like the WSGI ``start_response()`` callable.  Instead,
applications and middleware convey the HTTP response in total via a single
return value (the above response tuple).

This allows middleware to easily inspect (or even modify) any aspect of the
request or response all within a single call to their ``__call__()`` method.
This design also makes it easier to unit test applications, middleware, and even
servers.

Note that the HTTP *status* code is returned as an integer, and the *reason* is
returned as a separate string value (whereas in WSGI, both are provided together
via a single *status* string).  A general design theme in RGI is that values
should be kept in their most useful and native form for as long as possible, so
that re-parsing isn't needed.  For example, the server might want to verify that
a ``'content-range'`` header is present when the *status* is ``206`` (Partial
Content).

Also note that the response headers are a dictionary instead of a WSGI-style
list of pairs.  The response header names must be casefolded with
``str.casefold()``, and the ``'content-length'``, if present, must be a
non-negative ``int``.



Examples
--------

A few examples will help make this clearer, and should especially help make it
clear why RGI is very middleware-friendly (and proxy-friendly) compared to WSGI.

For example, consider this simple RGI application:

>>> def demo_app(connection, request):
...     if request['method'] not in ('GET', 'HEAD'):
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'hello, world'
...     headers = {'content-length': len(body)}
...     return (200, 'OK', headers, body)
...

Here's what ``demo_app()`` returns for a suitable GET request:

>>> demo_app({}, {'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 12}, b'hello, world')

However, note that ``demo_app()`` isn't actually HTTP/1.1 compliant as it should
not return a response body for a HEAD request:

>>> demo_app({}, {'method': 'HEAD', 'path': []})
(200, 'OK', {'content-length': 12}, b'hello, world')

Now consider this example middleware that checks for just such a faulty
application and overrides its response:

>>> class Middleware:
...     def __init__(self, app):
...         self.app = app
...
...     def __call__(self, connection, request):
...         (status, reason, headers, body) = self.app(connection, request)
...         if request['method'] == 'HEAD' and body is not None:
...             return (500, 'Internal Server Error', {}, None)
...         return (status, reason, headers, body)
...

``Middleware`` will let the response to a GET request pass through unchanged: 

>>> middleware = Middleware(demo_app)
>>> middleware({}, {'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 12}, b'hello, world')

But ``Middleware`` will intercept the faulty response to a HEAD request:

>>> middleware({}, {'method': 'HEAD', 'path': []})
(500, 'Internal Server Error', {}, None)



WSGI to RGI
-----------

Here's a table of common WSGI to RGI equivalents when handling requests:

==============================  ========================================
WSGI                            RGI
==============================  ========================================
``environ['wsgi.url_scheme']``  ``connection['scheme']``
``environ['SERVER_PROTOCOL']``  ``connection['protocol']``
``environ['SERVER_NAME']``      ``connection['server'][0]``
``environ['SERVER_PORT']``      ``connection['server'][1]``
``environ['REMOTE_ADDR']``      ``connection['client'][0]``
``environ['REMOTE_PORT']``      ``connection['client'][1]``
``environ['REQUEST_METHOD']``   ``request['method']``
``environ['SCRIPT_NAME']``      ``request['script']``
``environ['PATH_INFO']``        ``request['path']``
``environ['QUERY_STRING']``     ``request['query']``
``environ['CONTENT_TYPE']``     ``request['headers']['content-type']``
``environ['CONTENT_LENGTH']``   ``request['headers']['content-length']``
``environ['HTTP_FOO']``         ``request['headers']['foo']``
``environ['HTTP_BAR_BAZ']``     ``request['headers']['bar-baz']``
``environ['wsgi.input']``       ``request['body']``
==============================  ========================================

Note that the above RGI equivalents for these *environ* variables:

    * ``environ['SERVER_NAME']``
    * ``environ['SERVER_PORT']``
    * ``environ['REMOTE_ADDR']``
    * ``environ['REMOTE_PORT']``

...will *only* be true when the socket family is ``AF_INET`` or ``AF_INET6``,
but will *not* be true when the socket family is ``AF_UNIX``.

An important distinction in the RGI specification, and in Degu as an
implementation, is that they directly expose (and use) the *address* from the
underlying Python3 `socket API`_.

To further clarify things with a specific application example, this simple WSGI
application:

>>> def wsgi_app(environ, start_response):
...     if environ['REQUEST_METHOD'] not in {'GET', 'HEAD'}:
...         start_response('405 Method Not Allowed', [])
...         return []
...     body = b'hello, world'
...     headers = [
...         ('Content-Length', str(len(body))),
...         ('Content-Type', 'text/plain'),
...     ]
...     start_response('200 OK', headers)
...     if environ['REQUEST_METHOD'] == 'GET':
...         return [body]
...     return []  # No response body for HEAD

Would translate into this RGI application:

>>> def rgi_app(connection, request):
...     if request['method'] not in {'GET', 'HEAD'}:
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'hello, world'
...     headers = {
...         'content-length': len(body),
...         'content-type': 'text/plain',
...     }
...     if request['method'] == 'GET':
...         return (200, 'OK', headers, body)
...     return (200, 'OK', headers, None)  # No response body for HEAD

Also note that most RGI applications will probably ignore the information in the
*connection* argument when handling requests.  However, when needed, the
separation between per-connection state and per-request state offers unique
possibilities provided by few (if any) current HTTP server application APIs.



.. _`WSGI`: http://www.python.org/dev/peps/pep-3333/
.. _`CGI`: http://en.wikipedia.org/wiki/Common_Gateway_Interface
.. _`Dmedia`: https://launchpad.net/dmedia
.. _`socket API`: https://docs.python.org/3/library/socket.html
