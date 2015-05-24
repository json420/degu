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


Header values
-------------

:class:`Range`
''''''''''''''

.. class:: Range(start, stop)

    Used to represent the value of an HTTP Range header.

    The *start* and *stop* arguments must both be an ``int`` such that::

        0 <= start < stop

    Note that *start* and *stop* are interpreted as they would be in a Python
    ``slice()``, with the caveat that for a :class:`Range`, both must always be
    provided and neither can be negative.

    The Content-Length of what's being requesting via a :class:`Range` object
    is::

        content_length = stop - start

    :meth:`Range.__str__()` will return the rendered Range header value,
    automatically converting standard ``[start:stop]`` programming semantics to
    the rather awkward (and arguably incorrect) semantics of the HTTP Range
    header.

    For example, a request for ``b'tho'`` in ``b'Python'``:

    >>> from degu.base import Range
    >>> 'Python'[2:5]
    'tho'
    >>> r = Range(2, 5)
    >>> 'Python'[r.start:r.stop]
    'tho'

    Results in this Range header value:

    >>> str(r)
    'bytes=2-4'

    On the client-side, :meth:`degu.client.Connection.get_range()` will
    automatically create a :class:`Range` object for you and add it to your
    request headers.

    On the server-side, a Range header in the request preamble will
    automatically be converted to a :class:`Range` object after validation.

    .. attribute:: start

        The *start* value passed to the constructor.

    .. attribute:: stop

        The *stop* value passed to the constructor.

    .. method:: __str__()

        Render the Range header value as a ``str``.

        For example:

        >>> from degu.base import Range
        >>> value = Range(50, 100)
        >>> str(value)
        'bytes=50-99'


:class:`ContentRange`
'''''''''''''''''''''

.. class:: ContentRange(start, stop, total)

    Used to represent the value of an HTTP Content-Range header.

    The *start*, *stop*, and *total* arguments must all an ``int`` such that::

        0 <= start < stop <= total

    >>> from degu.base import ContentRange
    >>> value = ContentRange(50, 100, 200)
    >>> str(value)
    'bytes 50-99/200'

    .. attribute:: start

        The *start* value passed to the constructor.

    .. attribute:: stop

        The *stop* value passed to the constructor.

    .. attribute:: total

        The *total* value passed to the constructor.

    .. method:: __str__()

        Render the Content-Range header value as a ``str``.

        For example:

        >>> from degu.base import ContentRange
        >>> value = ContentRange(50, 100, 200)
        >>> str(value)
        'bytes 50-99/200'


:class:`Bodies` namedtuple
--------------------------

.. class:: Bodies(Body, ChunkedBody, BodyIter, ChunkedBodyIter)

    An instances of this namedtuple is used to expose the IO abstraction API.

    .. attribute:: Body

        The :class:`Body` class.
        
    .. attribute:: ChunkedBody

        The :class:`ChunkedBody` class.

    .. attribute:: BodyIter

        The :class:`BodyIter` class.

    .. attribute:: ChunkedBodyIter

        The :class:`ChunkedBodyIter` class.



:attr:`bodies`
--------------


.. data:: bodies

    The :class:`Bodies` instance exposing the Degu IO abstraction API.

    >>> from degu.base import bodies
    >>> bodies
    Bodies(Body=<class 'degu._base.Body'>, ChunkedBody=<class 'degu._base.ChunkedBody'>, BodyIter=<class 'degu._base.BodyIter'>, ChunkedBodyIter=<class 'degu._base.ChunkedBodyIter'>)


Input/output bodies
-------------------

:class:`Body` and :class:`ChunkedBody` are internally used by Degu to expose
HTTP input bodies.

Degu consumers can likewise use them to specify an HTTP output body.


:class:`Body`
'''''''''''''

.. class:: Body(rfile, content_length)

    An HTTP input or output body with a content-length.

    The *rfile* argument must have ``readinto()`` method::

        rfile.readinto(dst_buf) --> int (number of bytes read)

    (See `io.RawIOBase.readinto()`_ for details.)

    The *content_length* argument must be a non-negative ``int`` specifying the
    expected Content-Length.

    A :class:`Body` wont read more than the specified *content_length* from
    *rfile*, and will likewise raise a ``ValueError`` is less than the specified
    *content_length* can be read from *rfile*.

    .. attribute:: chunked

        Always ``False``, indicating this body has a content-length.

        This attribute allows you to determine whether an HTTP input body is
        chunk-encoded without having to check the exact Python object type.

    .. attribute:: rfile

        The *rfile* passed to the constructor

    .. attribute:: content_length

        The *content_length* passed to the constructor.

    .. method:: __iter__()

        Iterate through all the data in the HTTP body.

        This method will yield the entire HTTP body as a series of ``bytes``
        instance.

    .. method:: read(size=None)

        Read part (or all) of the HTTP body.

        If no *size* argument is provided, the entire remaining HTTP body will
        be returned as a single ``bytes`` instance.

        If the *size* argument is provided, up to that many bytes will be read
        and returned from the HTTP body.

    .. method:: write_to(wfile)

        Write this entire HTTP body to *wfile*.

        The *wfile* argument must have a ``write()`` method::

            wfile.write(src_buf) --> int (number of bytes written)

        (See `io.RawIOBase.write()`_ for details.)


:class:`ChunkedBody`
''''''''''''''''''''


.. class:: ChunkedBody(rfile)

    A chunk-encoded HTTP input or output body.

    The *rfile* argument must have ``readline()`` and ``readinto()`` methods::

        rfile.readline(size)    --> bytes (the line as Python3 bytes)
        rfile.readinto(dst_buf) --> int   (number of bytes read)

    (See `io.IOBase.readline()`_ and `io.RawIOBase.readinto()`_ for details.)

    If you iterate through a :class:`ChunkedBody` instance, it will yield an
    ``(extension, data)`` tuple for each chunk in the chunk-encoded stream.  For
    example:

    >>> from io import BytesIO
    >>> from degu.base import bodies
    >>> rfile = BytesIO(b'5\r\nhello\r\n5;foo=bar\r\nworld\r\n0\r\n\r\n')
    >>> body = bodies.ChunkedBody(rfile)
    >>> list(body)
    [(None, b'hello'), (('foo', 'bar'), b'world'), (None, b'')]

    A :class:`ChunkedBody` will read from *rfile* up till the first empty
    chunk is encountered, after which the body is considered fully consumed.

    A ``ValueError`` will be raised if any chunks are mall-formed or if at least
    one chunk with empty data can't be read from *rfile*.

    .. attribute:: chunked

        Always ``True``, indicating this body is chunk-encoded HTTP.

        This attribute allows you to determine whether an HTTP input body is
        chunk-encoded without having to check the exact Python object type.

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

    .. method:: write_to(wfile)

        Write this entire HTTP body to *wfile*.

        The *wfile* argument must have a ``write()`` method::

            wfile.write(src_buf) --> int (number of bytes written)

        (See `io.RawIOBase.write()`_ for details.)


Output bodies
-------------

Degu consumers can use a :class:`BodyIter` or a :class:`ChunkedBodyIter` to
specify an HTTP output body that will be generated from an abritrary iterable
object.

:class:`ChunkedBodyIter` can also be quite handy for unit testing, for example:

>>> from io import BytesIO
>>> from degu.base import bodies
>>> source = [(None, b'my'), (None, b'chunks'), (None, b'')]
>>> body = bodies.ChunkedBodyIter(source)
>>> wfile = BytesIO()
>>> body.write_to(wfile)
23
>>> wfile.getvalue()
b'2\r\nmy\r\n6\r\nchunks\r\n0\r\n\r\n'


:class:`BodyIter`
'''''''''''''''''

.. class:: BodyIter(source, content_length)

    An HTTP output body with a content-length.

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

    .. method:: write_to(wfile)

        Write this entire HTTP body to *wfile*.

        The *wfile* argument must have a ``write()`` method::

            wfile.write(src_buf) --> int (number of bytes written)

        (See `io.RawIOBase.write()`_ for details.)



:class:`ChunkedBodyIter`
''''''''''''''''''''''''

.. class:: ChunkedBodyIter(source)

    A chunk-encoded HTTP output body.

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

    .. method:: write_to(wfile)

        Write this entire HTTP body to *wfile*.

        The *wfile* argument must have a ``write()`` method::

            wfile.write(src_buf) --> int (number of bytes written)

        (See `io.RawIOBase.write()`_ for details.)




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

.. _`io.RawIOBase.readinto()`: https://docs.python.org/3/library/io.html#io.RawIOBase.readinto
.. _`io.RawIOBase.write()`: https://docs.python.org/3/library/io.html#io.RawIOBase.write
.. _`io.IOBase.readline()`: https://docs.python.org/3/library/io.html#io.IOBase.readline

