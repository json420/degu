:mod:`degu.base` --- parser and IO abstractions
===============================================

.. module:: degu.base
   :synopsis: common HTTP parser and IO abstractions

This module provides the low level HTTP parser and IO abstractions used by both
:mod:`degu.server` and :mod:`degu.client`.


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



