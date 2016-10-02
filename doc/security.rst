Security Considerations
=======================

Just enough HTTP
----------------

A central design goal for Degu is reducing HTTP to a minimal and manageable
amount of attack surface.

As such, Degu only supports the HTTP feature that are truly needed for its use
case, and Degu seldom supports alternate ways of expressing the same thing (the
exception being that incoming HTTP header names can be mixed case, although note
that outgoing header names must always be lower case).

Although Degu is more strict and minimal than most HTTP servers and clients, in
practice this isn't particularly limiting.  Degu is regularly used in production
with other HTTP servers and clients.

The goal is to strike the right balance between utility and attack surface.  In
many ways, Degu provides more utility than many HTTP severs and clients,
especially because Degu fully exposes HTTP chunked transfer-encoding semantics.
But if you find that Degu is too strict for your use-case, please `file a bug`_
and we'll consider relaxing these restrictions to accommodate your use case.


Reading the preamble
--------------------

Degu does no incremental parsing as the HTTP preamble is read.  Instead, Degu
makes successive calls to `socket.socket.recv_into()`_ till the preamble
terminator (``b'\r\n\r\n'``) is found or till the maximum preamble size is
exceeded (currently 32 KiB).

Assuming the preamble terminator is found within the first 32 KiB, the entire
preamble (minus the ``b'\r\n\r\n'`` terminator) is passed to the internal
parsing API as a read-only buffer.

This approach allows Degu to completely decouple reading the preamble from
parsing the preamble, which makes the Degu parser easier to reason about and
easier to exhaustively unit test.  In particular, this approach means that the
parser itself cannot directly invoke further reads.


Parsing the preamble
--------------------

Degu strictly validates what byte values are allowed in each region of the HTTP
preamble.

For example, these are the current validation tables used in the pure-Python
reference implementation::

    ################    BEGIN GENERATED TABLES    ##################################
    NAME = frozenset(
        b'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    )

    DECIMAL = frozenset(b'0123456789')
    HEXADECIMAL = frozenset(b'0123456789ABCDEFabcdef')

    _LOWER = b'-0123456789abcdefghijklmnopqrstuvwxyz'
    _UPPER = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    _URI   = b'/?'
    _PATH  = b'+.:_~'
    _QUERY = b'%&='
    _SPACE = b' '
    _VALUE = b'"\'()*,;[]'

    KEY    = frozenset(_LOWER)
    VAL    = frozenset(_LOWER + _UPPER + _PATH + _QUERY + _URI + _SPACE + _VALUE)
    URI    = frozenset(_LOWER + _UPPER + _PATH + _QUERY + _URI)
    PATH   = frozenset(_LOWER + _UPPER + _PATH)
    QUERY  = frozenset(_LOWER + _UPPER + _PATH + _QUERY)
    REASON = frozenset(_LOWER + _UPPER + _SPACE)
    EXTKEY = frozenset(_LOWER + _UPPER)
    EXTVAL = frozenset(_LOWER + _UPPER + _PATH + _VALUE)
    ################    END GENERATED TABLES      ##################################

Also see the equivalent tables in `degu/_base.h`_ used by the C implementation.

And see `degu/tables.py`_ for details on how these tables are generated.


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


.. _`file a bug`: https://bugs.launchpad.net/degu
.. _`socket.socket.recv_into()`: https://docs.python.org/3/library/socket.html#socket.socket.recv_into
.. _`degu/_base.h`: https://bazaar.launchpad.net/~dmedia/degu/trunk/view/head:/degu/_base.h
.. _`degu/tables.py`: https://bazaar.launchpad.net/~dmedia/degu/trunk/view/head:/degu/tables.py

