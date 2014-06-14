:mod:`degu.base` --- parser and IO abstractions
===============================================

.. module:: degu.base
   :synopsis: common HTTP parser and IO abstractions

This module provides the low level HTTP parser and IO abstractions used by both
:mod:`degu.server` and :mod:`degu.client`.

.. warning::

    The :mod:`degu.base` API in particular is not yet stable, will likely still
    undergo fairly dramatic change as the dust settles.  It is documented to
    help you understand how Degu is implemented, but you should really use the
    higher level API in :mod:`degu.server` and :mod:`degu.client`.



Exceptions
----------

.. exception:: EmptyPreambleError

    Raised by :func:`read_preamble()` when no data is received.

    This is a ``ConnectionError`` subclass.  When no data is received when
    trying to read the request or response preamble, this typically means the
    connection was closed on the other end.

    This exception is inspired by the `BadStatusLine`_ exception in the
    ``http.client`` module in the standard Python3 library.  However, as
    :exc:`EmptyPreambleError` is a ``ConnectionError`` subclass, there is no
    reason to use this exception directly.



Parsing functions
-----------------


.. function:: read_preamble(rfile)

    Read the HTTP request or response preamble, do low-level parsing.

    The return value will be a ``(first_line, header_lines)`` tuple.

    For example:

    >>> import io
    >>> from degu.base import read_preamble
    >>> rfile = io.BytesIO(b'first-line\r\nheader1-line\r\nheader2-line\r\n\r\n')
    >>> read_preamble(rfile)
    ('first-line', ['header1-line', 'header2-line'])

    High-level parsing of the ``header_lines`` should be done with
    :func:`parse_headers()`.


.. function:: read_chunk(rfile)

    Read a chunk from a chunk-encoded request or response body.

    For example:

    >>> import io
    >>> from degu.base import read_chunk
    >>> rfile = io.BytesIO(b'5\r\nhello\r\n')
    >>> read_chunk(rfile)
    b'hello'

    For more details, see `Chunked Transfer Coding`_ in the HTTP/1.1 spec.

    Note this function currently ignores any chunk-extension that may be
    present.


.. function:: write_chunk(wfile, chunk)

    Write a chunk to a chunk-encoded request or response body.

    The return value will be the total bytes written, including the chunk size
    line and the final CRLF chunk data terminator.

    For example:

    >>> import io
    >>> from degu.base import write_chunk
    >>> wfile = io.BytesIO()
    >>> write_chunk(wfile, b'hello')
    10
    >>> wfile.getvalue()
    b'5\r\nhello\r\n'

    For more details, see `Chunked Transfer Coding`_ in the HTTP/1.1 spec.

    Note this function currently doesn't support chunk-extensions.


.. function:: parse_headers(header_lines)

    Parse *header_lines* into a dictionary with case-folded (lowercase) keys.

    The return value will be a ``dict`` mapping header names to header values,
    and the header names will be case-folded (lowercase).  For example:

    >>> from degu.base import parse_headers
    >>> parse_headers(['Content-Type: application/json'])
    {'content-type': 'application/json'}

    Although allowed by HTTP/1.1 (but seldom used in practice), this function
    does not permit multiple occurrences of the same header name:

    >>> lines = ['content-type: foo/bar', 'Content-Type: stuff/junk']
    >>> parse_headers(lines)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: duplicates in header_lines:
      content-type: foo/bar
      Content-Type: stuff/junk

    If a Content-Length header is included, its value will be parsed into an
    ``int`` and validated:

    >>> parse_headers(['Content-Length: 1776'])
    {'content-length': 1776}

    A ``ValueError`` is raised if the Content-Length can't be parsed into an
    integer:

    >>> parse_headers(['Content-Length: E81F3B'])  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: invalid literal for int() with base 10: 'E81F3B'

    Likewise, a ``ValueError`` is raised if the Content-Length is negative:

    >>> parse_headers(['Content-Length: -42'])  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: negative content-length: -42

    If a Transfer-Encoding header is included, this functions will raise a
    ``ValueError`` if the value is anything other than ``'chunked'``.

    >>> parse_headers(['Transfer-Encoding: clumped'])  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: bad transfer-encoding: 'clumped'

    Finally, this function will also raise a ``ValueError`` if both
    Content-Length and Transfer-Encoding headers are included:

    >>> lines = ['Transfer-Encoding: chunked', 'Content-Length: 1776']
    >>> parse_headers(lines)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: cannot have both content-length and transfer-encoding headers



Input wrappers
--------------

In the server context, these input abstractions represent the HTTP request body
sent by the client.

In the client context, they represent the HTTP response body sent by the server.


.. class:: Input(rfile, content_length)

    Represents a normal (non-chunk-encoded) HTTP request or response body.

    .. attribute:: rfile
    
        The *rfile* passed to the constructor

    .. attribute:: content_length

        The *content_length* passed to the constructor.

    .. attribute:: remaining

        Remaining bytes available for reading in the HTTP body.

        This attribute is initially set to :attr:`Input.content_length`.  Once
        the entire HTTP body has been read, this attribute will be ``0``.

    .. attribute:: closed

        Initially ``False``, will be ``True`` after entire body has been read.

    .. attribute:: chunked

        Always ``False``, indicating a normal (non-chunk-encoded) HTTP body.

        This attribute exists so that RGI applications can test whether an HTTP
        body is chunk-encoded without having to check whether the body is an
        instance of a particular class.

        This allows the same input abstraction API to be easily used with any
        RGI compliant server implementation, not just the Degu reference server.

    .. method:: read(size=None)

        Read part (or all) of the HTTP body.

        If no *size* argument is provided, the entire HTTP body will be returned
        as a single ``bytes`` instance.

        If the *size* argument is provided, up to that many bytes will be read
        and returned from the HTTP body.

        If the entire HTTP body has already been read, this method will return
        an empty ``b''``.

    .. method:: __iter__()

        Iterate through all the data in the HTTP body.

        This method will yield the entire HTTP body as a series of ``bytes``
        instances each up to 1 MiB in size.

        The final item yielded will always be an empty ``b''``.

        Note that you can only iterate through an :class:`Input` instance once.


.. class:: ChunkedInput(rfile)

    Represents a chunk-encoded HTTP request or response body.

    .. attribute:: rfile
    
        The *rfile* passed to the constructor

    .. attribute:: closed

        Initially ``False``, will be ``True`` after entire body has been read.

    .. attribute:: chunked

        Always ``True``, indicating a chunk-encoded HTTP body.

        This attribute exists so that RGI applications can test whether an HTTP
        body is chunk-encoded without having to check whether the body is an
        instance of a particular class.

        This allows the same input abstraction API to be easily used with any
        RGI compliant server implementation, not just the Degu reference server.

    .. method:: read()

        Read the entire HTTP body.

        This method will return the concatenated chunks from a chunk-encoded
        HTTP body as a single ``bytes`` instance.

        If the entire HTTP body has already been read, this method will return
        an empty ``b''``.

    .. method:: readchunk()

        Read the next chunk from the chunk-encoded HTTP body.

        If all chunks have already been read from the chunk-encoded HTTP body,
        this method will return an empty ``b''``.

        Note that the final chunk will likewise be an empty ``b''``.

    .. method:: __iter__()

        Iterate through chunks in the chunk-encoded HTTP body.

        This method will yield the HTTP body as a series of ``bytes`` instances
        of whatever size the corresponding data chunks are in the chunk-encoded
        HTTP body.

        The final item yielded will always be an empty ``b''``.

        Note that you can only iterate through a :class:`ChunkedInput` instance
        once.



Output wrappers
---------------

In the server context, these output abstractions represent the HTTP response
body that the server is sending to the client.

In the client context, they represent the HTTP request body that the client is
sending to the server.


.. class:: Output(source, content_length)

    Wraps output of known content-length to be written to the rfile.



.. class:: ChunkedOutput(source)

    Wraps output to be written to the rfile using chunked encoding.


.. class:: FileOutput(fp, content_length)

    Wraps output to be written to the rfile, read from an open file *fp*.



.. _`Chunked Transfer Coding`: http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
.. _`BadStatusLine`: https://docs.python.org/3/library/http.client.html#http.client.BadStatusLine
