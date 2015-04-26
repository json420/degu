:mod:`degu.base` --- Bodies API, parser, formatter
==================================================

.. module:: degu.base
   :synopsis: HTTP bodies API, parser, formatter

:mod:`degu.base` provides IO abstractions used by both :mod:`degu.server` and
:mod:`degu.client` to represent HTTP request and response bodies.  This API is
exposed via the :attr:`bodies` attribute, which is a :class:`BodiesAPI`
instance.

This module also provides the shared HTTP parser and formatter used by the Degu
server and client.

However, aside from :func:`read_chunk()` and :func:`write_chunk()`, the parsing
and formatting API is still private, for Degu internal use only, with no
commitment to backward API compatibility.

But the parsing and formatting API isn't something 3rd-party applications need
to use directly.  It's just something that will *eventually* be exposed as part
of the stable Degu API, largely because it can be handy for unit testing and, if
nothing else, helpful in understanding how Degu is implemented.

Some :mod:`degu.base` functionality is already implemented in a high-performance
`C extension`_, with a pure-Python reference implementation of the same to help
verify the correctness of the C extension.

Over time, most (if not all) of :mod:`degu.base` will be implemented in C, again
with a pure-Python reference implementation to help verify the correctness of
the C implementation.



Exceptions
----------

.. exception:: EmptyPreambleError

    Raised when ``b''`` is returned when reading the HTTP preamble.

    This is a ``ConnectionError`` subclass.  When no data is received when
    trying to read the request or response preamble, this typically means the
    connection was closed on the other end.

    This exception is inspired by the `BadStatusLine`_ exception in the
    ``http.client`` module in the standard Python3 library.  However, as
    :exc:`EmptyPreambleError` is a ``ConnectionError`` subclass, there is no
    reason to use this exception directly.

    Instead just except a ``ConnectionError``, as this also captures other
    scenarios that your application will want to treat as equivalent (all
    being interpreted as "oops, the connection to the other endpoint was
    closed").

    For example::

        try:
            response = conn.request('GET', '/foo/bar', {}, None)
        except ConnectionError:
            pass  # Retry?  Give up?  Your choice!



Constants
---------

.. data:: MAX_READ_SIZE

    Max total read size (in bytes).

    >>> from degu import base
    >>> base.MAX_READ_SIZE  # 16 MiB
    16777216

.. data:: MAX_CHUNK_SIZE

    Max total read size (in bytes).

    >>> from degu import base
    >>> base.MAX_CHUNK_SIZE  # 16 MiB
    16777216

.. data:: IO_SIZE

    Default IO size for :class:`Body` (in bytes).

    >>> from degu import base
    >>> base.IO_SIZE  # 1 MiB
    1048576




:class:`BodiesAPI`
------------------

.. class:: BodiesAPI(Body, BodyIter, ChunkedBody, ChunkedBodyIter)

    Instances of this namedtuple are used to expose the IO abstraction API.

    .. attribute:: Body

        1st argument passed to constructor.

    .. attribute:: BodyIter

        2nd argument passed to constructor.

    .. attribute:: ChunkedBody

        3rd argument passed to constructor.

    .. attribute:: ChunkedBodyIter

        4th argument passed to constructor.



:attr:`bodies`
--------------


.. data:: bodies

    A :class:`BodiesAPI` instance exposing the standard Degu IO abstraction API.

    This uses the Degu reference implementation of the four IO abstraction
    classes:

        * :class:`Body`
        * :class:`BodyIter`
        * :class:`ChunkedBody`
        * :class:`ChunkedBodyIter`



:class:`Body`
'''''''''''''

.. class:: Body(rfile, content_length, io_size=IO_SIZE)

    Represents an HTTP request or response body with a content-length.

    This class provides HTTP Content-Length based framing atop an arbitrary
    buffered binary stream (basically, anything that has a ``read()`` method
    that returns ``bytes``, and also has a ``close()`` method).

    :meth:`Body.read()` is designed to enforce TCP request/response stream-state
    consistency:

        * It wont allow reading of data from the underlying *rfile* beyond the
          specified *content_length*

        * If less data than the claimed *content_length* can be read from
          *rfile*, it will close the underlying *rfile* and raise an exception

    The *rfile* can be a normal file created with ``open(filename, 'rb')``, or
    a file-object returned by `socket.socket.makefile()`_, or any other similar
    object implementing the needed API.

    .. attribute:: rfile

        The *rfile* passed to the constructor

    .. attribute:: content_length

        The *content_length* passed to the constructor.

    .. attribute:: io_size

        Value of optional *io_size* argument passed to the constructor.

        If *io_size* was not provided, it defaults to :data:`IO_SIZE` (1
        MiB).

    .. attribute:: chunked

        Always ``False``, indicating a normal (non-chunk-encoded) HTTP body.

        This attribute exists so that RGI applications can test whether an HTTP
        body is chunk-encoded without having to check whether the body is an
        instance of a particular class.

        This allows the same HTTP body abstraction API to be easily used with
        any RGI compliant server implementation, not just the Degu reference
        server.

    .. attribute:: closed

        Initially ``False``, will be ``True`` after entire body has been read.

    .. method:: __iter__()

        Iterate through all the data in the HTTP body.

        This method will yield the entire HTTP body as a series of ``bytes``
        instances each up to :attr:`Body.io_size` bytes in size.

        Note that you can only iterate through an :class:`Body` instance once.

    .. method:: read(size=None)

        Read part (or all) of the HTTP body.

        If no *size* argument is provided, the entire remaining HTTP body will
        be returned as a single ``bytes`` instance.

        If the *size* argument is provided, up to that many bytes will be read
        and returned from the HTTP body.

    .. method:: write_to(wfile)

        Write this entire HTTP body to *wfile*.

        *wfile* must be a Python file-like object with at least
        ``wfile.write()`` and ``wfile.flush()`` methods.



:class:`BodyIter`
'''''''''''''''''

.. class:: BodyIter(source, content_length)

    Wraps an iterable to construct an HTTP output body with a content-length.

    This class allows an output HTTP body to be piecewise generated on-the-fly,
    but still with an explicit agreement about what the final content-length
    will be.

    On the client side, this can be used to generate the client request body.

    On the server side, this can be used to generate the server response body.

    Items in *source* can be of any size, including empty, as long as the total
    size matches the claimed *content_length*.  For example:

    >>> import io
    >>> from degu.base import bodies
    >>> def generate_body():
    ...     yield b''
    ...     yield b'hello'
    ...     yield b', '
    ...     yield b'world'
    ...
    >>> body = bodies.BodyIter(generate_body(), 12)
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)
    12
    >>> wfile.getvalue()
    b'hello, world'

    You can only call :meth:`BodyIter.write_to()` once.  Subsequent calls will
    raise a ``ValueError``:
    
    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: BodyIter.state == BODY_CONSUMED, already consumed

    A ``ValueError`` will be raised in the total produced by *source* is less
    than *content_length*:

    >>> body = bodies.BodyIter(generate_body(), 13)
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: deceeds content_length: 12 < 13

    Likewise, a ``ValueError`` will be raised if the total produced by *source*
    is greater than *content_length*:

    >>> body = bodies.BodyIter(generate_body(), 11)
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: exceeds content_length: 12 > 11


    .. attribute:: source

        The *source* iterable passed to the constructor.

    .. attribute:: content_length

        The *content_length* passed to the constructor.

    .. attribute:: closed

        Initially ``False``, will be ``True`` after body is fully consumed.

    .. method:: write_to(wfile)

        Write to *wfile*.



:class:`ChunkedBody`
''''''''''''''''''''


.. class:: ChunkedBody(rfile)

    Represents a chunk-encoded HTTP request or response body.

    This class provides HTTP chunked Transfer-Encoding based framing atop an
    arbitrary buffered binary stream (basically, anything that has ``read()``
    and ``readline()`` methods that return ``bytes``, and also has a ``close()``
    method).

    :meth:`ChunkedBody.readchunk()` is designed to enforce TCP request/response
    stream-state consistency:

        * It wont read data from *rfile* past the end of the final (empty) HTTP
          chunk-encoded chunk

        * If an improperly encoded chunk is found, or *rfile* can't produce as
          much data for a chunk as specified by the chunk size line, the
          underlying *rfile* will be closed and an exception will be raised

    The *rfile* can be a normal file created with ``open(filename, 'rb')``, or
    a file-object returned by `socket.socket.makefile()`_, or any other similar
    object implementing the needed API.

    If you iterate through a :class:`ChunkedBody` instance, it will yield a
    ``(extension, data)`` tuple for each chunk in the chunk-encoded stream.  For
    example:

    >>> from io import BytesIO
    >>> from degu.base import bodies
    >>> rfile = BytesIO(b'5\r\nhello\r\n5;foo=bar\r\nworld\r\n0\r\n\r\n')
    >>> body = bodies.ChunkedBody(rfile)
    >>> list(body)
    [(None, b'hello'), (('foo', 'bar'), b'world'), (None, b'')]

    Note that you can only iterate through a :class:`ChunkedBody` once:

    >>> list(body)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: ChunkedBody.state == BODY_CONSUMED, already consumed

    .. attribute:: chunked

        Always ``True``, indicating a chunk-encoded HTTP body.

        This attribute exists so that RGI applications can test whether an HTTP
        body is chunk-encoded without having to check whether the body is an
        instance of a particular class.

        This allows the same HTTP body abstraction API to be easily used with
        any RGI compliant server implementation, not just the Degu reference
        server.

    .. attribute:: closed

        Initially ``False``, will be ``True`` after entire body has been read.

    .. attribute:: rfile
    
        The *rfile* passed to the constructor

    .. method:: readchunk()

        Read the next chunk from the chunk-encoded HTTP body.

        If all chunks have already been read from the chunk-encoded HTTP body,
        this method will return an empty ``b''``.

        Note that the final chunk will likewise be an empty ``b''``.

    .. method:: read()

        Read the entire HTTP body.

        This method will return the concatenated chunks from a chunk-encoded
        HTTP body as a single ``bytes`` instance.

        If the entire HTTP body has already been read, this method will return
        an empty ``b''``.

    .. method:: __iter__()

        Iterate through chunks in the chunk-encoded HTTP body.

        This method will yield the HTTP body as a series of
        ``(extension, data)`` tuples for each chunk in the body.

        The final item yielded will always be an empty ``b''`` *data*.

        Note that you can only iterate through a :class:`ChunkedBody` instance
        once.


:class:`ChunkedBodyIter`
''''''''''''''''''''''''

.. class:: ChunkedBodyIter(source)

    Wraps an interable to construct a chunk-encoded HTTP output body.

    This class allows a chunked-encoded HTTP body to be piecewise generated
    on-the-fly.

    On the client side, this can be used to generate the client request body.

    On the server side, this can be used to generate the server response body.

    *source* must yield a series of ``(extension, data)`` tuples, and must
    always yield at least one item.

    The final ``(extension, data)`` item, and only the final item, must have
    an empty *data* value of ``b''``.

    For example:

    >>> import io
    >>> from degu.base import bodies
    >>> def generate_chunked_body():
    ...     yield (None,            b'hello')
    ...     yield (('foo', 'bar'),  b'world')
    ...     yield (None,            b'')
    ...
    >>> body = bodies.ChunkedBodyIter(generate_chunked_body())
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)
    33
    >>> wfile.getvalue()
    b'5\r\nhello\r\n5;foo=bar\r\nworld\r\n0\r\n\r\n'

    You can only call :meth:`ChunkedBodyIter.write_to()` once.  Subsequent calls
    will raise a ``ValueError``:

    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: ChunkedBodyIter.state == BODY_CONSUMED, already consumed

    A ``ValueError`` will be raised if the *data* in the final chunk isn't
    empty:

    >>> def generate_chunked_body():
    ...     yield (None,            b'hello')
    ...     yield (('foo', 'bar'),  b'world')
    ...
    >>> body = bodies.ChunkedBodyIter(generate_chunked_body())
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: final chunk data was not empty

    Likewise, a ``ValueError`` will be raised if a chunk with empty *data* is
    followed by a chunk with non-empty *data*:

    >>> def generate_chunked_body():
    ...     yield (None,  b'hello')
    ...     yield (None,  b'')
    ...     yield (None,  b'world')
    ...
    >>> body = bodies.ChunkedBodyIter(generate_chunked_body())
    >>> wfile = io.BytesIO()
    >>> body.write_to(wfile)  # doctest: -IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: additional chunk after empty chunk data

    .. attribute:: source

        The *source* iterable passed to the constructor.

    .. attribute:: closed

        Initially ``False``, will be ``True`` after body is fully consumed.

    .. method:: write_to(wfile)

        Write to *wfile*.



Parsing/formatting
------------------

.. function:: read_chunk(rfile)

    Read a chunk from a chunk-encoded request or response body.

    For example:

    >>> import io
    >>> from degu.base import read_chunk
    >>> rfile = io.BytesIO(b'5\r\nhello\r\n')
    >>> read_chunk(rfile)
    (None, b'hello')

    Or when there is a chunk extension:

    >>> rfile = io.BytesIO(b'5;foo=bar\r\nhello\r\n')
    >>> read_chunk(rfile)
    (('foo', 'bar'), b'hello')

    For more details, see `Chunked Transfer Coding`_ in the HTTP/1.1 spec.


.. function:: write_chunk(wfile, chunk)

    Write a chunk to a chunk-encoded request or response body.

    The *chunk* must be an ``(extension, data)`` tuple.  When there is no
    extension in the chunk, *extension* must be ``None``::

        (None, b'hello')

    Or when there is an extension in the chunk, *extension* must be a
    ``(key, value)`` tuple::

        (('foo', 'bar'), b'hello')

    The return value will be the total bytes written, including the chunk size
    line and the final CRLF chunk data terminator.

    For example:

    >>> import io
    >>> from degu.base import write_chunk
    >>> wfile = io.BytesIO()
    >>> chunk = (None, b'hello')
    >>> write_chunk(wfile, chunk)
    10
    >>> wfile.getvalue()
    b'5\r\nhello\r\n'

    Or when there is a chunk extension:

    >>> wfile = io.BytesIO()
    >>> chunk = (('foo', 'bar'), b'hello')
    >>> write_chunk(wfile, chunk)
    18
    >>> wfile.getvalue()
    b'5;foo=bar\r\nhello\r\n'

    For more details, see `Chunked Transfer Coding`_ in the HTTP/1.1 spec.




.. _`Chunked Transfer Coding`: http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6.1
.. _`BadStatusLine`: https://docs.python.org/3/library/http.client.html#http.client.BadStatusLine
.. _`socket.socket.makefile()`: https://docs.python.org/3/library/socket.html#socket.socket.makefile
.. _`C extension`: http://bazaar.launchpad.net/~dmedia/degu/trunk/view/head:/degu/_base.c
