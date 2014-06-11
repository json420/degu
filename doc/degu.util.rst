:mod:`degu.util` --- RGI application utilities
==============================================

.. module:: degu.util
   :synopsis: helpful utility functions for RGP server applications

This module provides utility functions useful to many RGI server applications.

Although this module is heavily inspired by the `wsgiref.util`_ module in the
Python3 standard library, it doesn't provide many direct equivalents, due to
differences in the :doc:`rgi` as a specification, and in the focus of `Degu`_ as
an implementation.



Functions
---------


.. function:: shift_path(request)

    Shift component from ``'path'`` to ``'script'`` in an RGI *request* argument.

    This is an extremely common need when it comes to request routing, and in
    particular for RGI middleware applications that do request routing.

    For example:

    >>> from degu.util import shift_path
    >>> request = {'script': ['foo'], 'path': ['bar', 'baz']}
    >>> shift_path(request)
    'bar'

    As you can see *request* was updated in place:

    >>> request['script']
    ['foo', 'bar']
    >>> request['path']
    ['baz']


.. function:: relative_uri(request)

    Reconstruct a relative URI from an RGI *request* argument.

    This function is especially useful for RGI reverse-proxy applications when
    building the URI used in their forwarded HTTP client request.

    For example, when there is no query:

    >>> from degu.util import relative_uri
    >>> request = {'path': ['bar', 'baz'], 'query': ''}
    >>> relative_uri(request)
    '/bar/baz'

    And when there is a query:

    >>> request = {'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> relative_uri(request)
    '/bar/baz?stuff=junk'

    Note that if present, ``request['script']`` is ignored by this function.
    If you need the original, absolute request URI, please use
    :func:`absolute_uri()`.


.. function:: absolute_uri(request)

    Create an absolute URI from an RGI *request* argument.

    For example, when there is no query:

    >>> from degu.util import absolute_uri
    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': ''}
    >>> absolute_uri(request)
    '/foo/bar/baz'

    And when there is a query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> absolute_uri(request)
    '/foo/bar/baz?stuff=junk'

    Note that in real-life scenarios this function probably wont be used as
    often as :func:`relative_uri()` because RGI application should generally be
    abstracted from their exact mount point within a REST API.


.. function:: output_from_input(connection, input_body)

    Create an RGI output abstraction instance from an RGI input abstraction.

    This function is especially useful for RGI reverse-proxy applications when
    building a client request body from a server request body, and when building
    a server response body from a client response body.

    The *connection* argument must have at least ``'rgi.Output'`` and
    ``'rgi.ChunkedOutput'`` keys, which specify the classes used for the return
    value instances, assuming the *input_body* isn't ``None``:

    >>> from degu import base
    >>> connection = {
    ...     'rgi.Output': base.Output,
    ...     'rgi.ChunkedOutput': base.ChunkedOutput,
    ... }
    ... 

    If the *input_body* is ``None``, then ``None`` will be returned:

    >>> from degu.util import output_from_input
    >>> output_from_input(connection, None) is None
    True

    Otherwise, if ``input_body.chunked`` is ``False``, then a
    ``connection['rgi.Output']`` instance wrapping the *input_body* is returned.
    Specifically, in Degu, if the *input_body* is a :class:`degu.base.Input`
    instance, then a :class:`degu.base.Output` instance is returned:

    >>> from io import BytesIO
    >>> rfile = BytesIO(b'hello, world')
    >>> input_body = base.Input(rfile, 12)
    >>> output_body = output_from_input(connection, input_body)
    >>> isinstance(output_body, base.Output)
    True
    >>> output_body.source is input_body
    True
    >>> list(output_body)
    [b'hello, world']

    Likewise, if ``input_body.chunked`` is ``True``, then a
    ``connection['rgi.ChunkedOutput']`` instance wrapping the *input_body* is
    returned.  Specifically, in Degu, if the *input_body* is a
    :class:`degu.base.ChunkedInput` instance, a :class:`degu.base.ChunkedOutput`
    instance is returned:

    >>> rfile = BytesIO(b'5\r\nhello\r\n7\r\nnaughty\r\n5\r\nnurse\r\n0\r\n\r\n')
    >>> input_body = base.ChunkedInput(rfile)
    >>> output_body = output_from_input(connection, input_body)
    >>> isinstance(output_body, base.ChunkedOutput)
    True
    >>> output_body.source is input_body
    True
    >>> list(output_body)
    [b'hello', b'naughty', b'nurse', b'']

    Note that the reason to pass the *connection* argument is so that this
    function is abstracted from the exact output wrapper classes used in RGI
    server implementations other than Degu (similar to the `WSGI`_
    ``environ['wsgi.file_wrapper']``).



.. _`wsgiref.util`: https://docs.python.org/3/library/wsgiref.html#module-wsgiref.util
.. _`Degu`: https://launchpad.net/degu
.. _`WSGI`: http://legacy.python.org/dev/peps/pep-3333/
