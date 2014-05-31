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

    >>> parse_headers(['content-type: foo/bar', 'Content-Type: stuff/junk'])
    Traceback (most recent call last):
      ...
    ValueError: duplicate header: 'content-type'

    If a Content-Length header is included, its value will be parsed into an
    ``int`` and validated:

    >>> parse_headers(['Content-Length: 1776'])
    {'content-length': 1776}

    A ``ValueError`` is raised if the Content-Length can't be parsed into an
    integer:

    >>> parse_headers(['Content-Length: E81F3B'])
    Traceback (most recent call last):
      ...
    ValueError: invalid literal for int() with base 10: 'E81F3B'

    Likewise, a ``ValueError`` is raised if the Content-Length is negative:

    >>> parse_headers(['Content-Length: -42'])
    Traceback (most recent call last):
      ...
    ValueError: negative content-length: -42

    If a Transfer-Encoding header is included, this functions will raise a
    ``ValueError`` if the value is anything other than ``'chunked'``.

    >>> parse_headers(['Transfer-Encoding: clumped'])
    Traceback (most recent call last):
      ...
    ValueError: bad transfer-encoding: 'clumped'

    Finally, this function will also raise a ``ValueError`` both Content-Length
    and Transfer-Encoding headers are included:

    >>> parse_headers(['Transfer-Encoding: chunked', 'Content-Length: 1776'])
    Traceback (most recent call last):
      ...
    ValueError: cannot have both 'content-length' and 'transfer-encoding' headers



Input abstractions
------------------

In the server context, these input abstractions represent the HTTP request body
sent by the client.

In the client context, they represent the HTTP response body sent by the server.


.. class:: Input(rfile, content_length)

    Read input from *rfile* when the *content_length* is known in advance.


.. class:: ChunkedInput(rfile)

    Read chunked-encoded input from *rfile*.



Output abstractions
-------------------

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
