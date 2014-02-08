REST Gateway Interface
======================

Note that this design is done out of deep respect for the `WSGI`_ standard.
Considering the delicate balance needed for compatibility on multiple fronts,
WSGI is an exceedingly good design.

*RGI* (REST Gateway Interface) is largely a thought experiment in what you could
do with something WSGI-like assuming you did *not* need `CGI`_ compatibility.

RGI focuses on improvement in a number of areas:

    1. Assuming you can drop CGI compatibility, the naming conventions in the
       WSGI *environ* leave much to be desired in terms of signal-to-noise ratio

    2. ``start_response()`` is the bane of middleware components because
       if they need to inspect or to modify the response status or response
       headers, they cannot simply pass to a WSGI application the same
       ``start_response()`` callable they received from the server

    3. A reverse proxy (aka gateway) application is a good model for the needs
       of middleware; in particular, we should not require middleware components
       to re-parse or otherwise transform any values in order to do something
       meaningful with these value (eg, a reverse proxy generally needs to use
       the full request headers in its own HTTP client request)

    4. Eliminate ambiguity about Transfer-Encoding vs Content-Length, in both
       the request body and the response body.


Birds Eye View
--------------

RGI applications take a single *request* argument, somewhat similar to the WSGI
*environ*.  For example:

>>> request = {
...     'method': 'POST',
...     'script': ['foo'],
...     'path': ['bar', 'baz'],
...     'query': 'hello=world',
...     'body': Input(rfile, content_length),  # Explained below
...     'headers': {
...         'accept': 'application/json',
...         'content-length': 1776,
...         'content-type': 'application/json',
...     },
... }


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

An RGI application must return a ``(status, reason, headers, body)`` response
tuple, for example:

>>> response = (200, 'OK', {'content-type': 'application/json'}, b'{"Hello": "World"}")

RGI doesn't use anything like the WSGI ``start_response()`` callable.  Instead,
applications and middleware convey the HTTP response in total via a single
return value (the above response tuple).

This allows middleware to easily inspect (or even modify) any aspect of the
request or response all within a single call to their ``__call__()`` method.
This design also makes it easier to unit test applications, middleware, and even
servers.

Note that the HTTP *status* code is returned as an integer, and the *reason* is
returned as a separate string value.  A general design theme in RGI is that
values should be kept in their most useful and native form for as long as
possible, so that re-parsing isn't needed.  For example, the server might want
to verify that a ``'content-range'`` header is present when the *status* is
``206`` (Partial Content).

Also note that the response headers are a dictionary instead of a WSGI-style
list of pairs.  The response header names must be casefolded with
``str.casefold()``, and the ``'content-length'``, if present, must be a
non-negative ``int``.


Examples
--------

A few examples will help make this clearer, and should especially help make it
clear why RGI is very middleware-friendly (and proxy-friendly) compared to WSGI.

For example, consider this simple RGI app:

>>> def demo_app(request):
...     if request['method'] not in ('GET', 'HEAD'):
...         return (405, 'Method Not Allowed', {}, None)
...     body = b'Hello, world!'
...     headers = {'content-length': len(body)}
...     return (200, 'OK', headers, body)
...

Here's what ``demo_app()`` returns for a suitable GET request:

>>> demo_app({'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

However, note that ``demo_app()`` isn't actually HTTP 1.1 compliant as it should
not return a response body for a HEAD request:

>>> demo_app({'method': 'HEAD', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

Now consider this example middleware that checks for just such a faulty
application and overrides its response:

>>> class Middleware:
...     def __init__(self, app):
...         self.app = app
...
...     def __call__(self, request):
...         (status, reason, headers, body) = self.app(request)
...         if request['method'] == 'HEAD' and body is not None:
...             return (500, 'Internal Server Error', {}, None)
...         return (status, reason, headers, body)
...

``Middleware`` will let the response to a GET request pass through unchanged: 

>>> middleware = Middleware(demo_app)
>>> middleware({'method': 'GET', 'path': []})
(200, 'OK', {'content-length': 13}, b'Hello, world!')

But ``Middleware`` will intercept the faulty response to a HEAD request:

>>> middleware({'method': 'HEAD', 'path': []})
(500, 'Internal Server Error', {}, None)

This pattern is very cumbersome with WSGI.


Request Body
------------



.. _`WSGI`: http://www.python.org/dev/peps/pep-3333/
.. _`CGI`: http://en.wikipedia.org/wiki/Common_Gateway_Interface
