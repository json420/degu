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

Degu uses a pair of tables to decode and validate in a single pass.
Additionally, the table for the KEYS set is constructed such that it case-folds
the header names as part of that same single pass.
