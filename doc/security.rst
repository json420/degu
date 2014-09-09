Security Considerations
=======================

HTTP preamble
-------------

The HTTP preamble is a hot bed of attack surface!

Degu aims to stop questionable input before it makes its way to other Python C
extensions, upstream HTTP servers, exploitable scenarios in Degu or CPython
themselves, or exploitable scenarios in 3rd party applications built atop Degu.

For this reason, Degu only allows a very constrained of set of bytes to exist in
the preamble (a subset of ASCII).

Note that Python's own codec handling is absolutely *not* secure for this
purpose!  Regardless of codec, ``bytes.decode()`` (and C API equivalents) will
happily include NUL bytes in the resulting ``str`` object:

>>> b'hello\x00world'.decode('ascii')
'hello\x00world'

Likewise, ``str.encode()`` (and the C API equivalents) will happily include
NUL bytes:

>>> 'hello\x00world'.encode('ascii')
b'hello\x00world'

Allowing the NUL byte is probably the most problematic aspect of
``bytes.decode()``, but there are certainly others as well.

Degu breaks down the preamble into two sets of allowed bytes:

    1. ``KEYS`` can contain any of these 63 bytes:

       >>> KEYS = b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
       >>> len(KEYS)
       63

    2. ``VALUES`` can contain anything in ``KEYS`` plus anything in these
       additional 32 bytes (for a total of 95 possible byte values):

       >>> VALUES = KEYS + b' !"#$%&\'()*+,./:;<=>?@[\\]^_`{|}~'
       >>> len(VALUES)
       95

The ``VALUES`` set applies to the first line in the preamble, and to header
values.  The more restrictive ``KEYS`` set applies to header names.

To explain this more visually, Degu validates the HTTP preamble according to
this structure::

    VALUES\r\n
    KEYS: VALUES\r\n
    KEYS: VALUES\r\n
    \r\n

Note that ``VALUES`` doesn't include ``b'\r'`` or ``b'\n'``.

Note that ``KEYS`` doesn't include ``b':'`` or ``b' '``.

The Degu C backend uses a pair of tables to decode and validate in a single
pass.  Additionally, the table for the KEYS set is constructed such that it
case-folds the header names as part of that same single pass.



Error handling
--------------

When an unhandled exception occurs at any point while handling a connection or
handling any requests for that connection, Degu will immediately shutdown the
connection and terminate its thread.

For security reasons, Degu does not convey anything about such errors through
any HTTP response.  A traceback will never be sent in a response body as
information in the traceback could potentially reveal secrets or other details
that could be used to further escalate an attack (for example, the memory
addresses of specific Python objects).

Likewise, not even something like a  **500 Internal Server Error** response
status is sent.  The connection is simply closed.  This is critical for security
because the TCP stream might be in an inconsistent state.  Under no circumstance
do we want an error condition to be able to create an inconsistent TCP stream
state such that some portion of an HTTP request body is read as the next HTTP
preamble.

