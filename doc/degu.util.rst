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

    Shift component from ``path`` to ``script`` in an RGI *request* argument.

    This is an extremely common need when it comes to request routing, and in
    particular for RGI middleware applications that do request routing.

    This function only use the ``path`` and ``script`` attributes from the
    :class:`degu.server.Request` namedtuple:

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'script path')

    Path shifting examples:

    >>> from degu.util import shift_path
    >>> request = Request(['foo'], ['bar', 'baz'])
    >>> shift_path(request)
    'bar'

    As you can see *request* was updated in place:

    >>> request
    Request(script=['foo', 'bar'], path=['baz'])

    An ``IndexError is raised if ``request.path`` is empty:

    >>> shift_path(request)
    'baz'
    >>> request
    Request(script=['foo', 'bar', 'baz'], path=[])
    >>> shift_path(request)
    Traceback (most recent call last):
      ...
    IndexError: pop from empty list


.. function:: relative_uri(request)

    Reconstruct a relative URI from an RGI *request* argument.

    This function is especially useful for RGI reverse-proxy applications when
    building the URI used in their forwarded HTTP client request.

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'path query')

    For example, when there is no query:

    >>> from degu.util import relative_uri
    >>> request = Request(['bar', 'baz'], None)
    >>> relative_uri(request)
    '/bar/baz'

    And when there is a query:

    >>> request = Request(['bar', 'baz'], 'stuff=junk')
    >>> relative_uri(request)
    '/bar/baz?stuff=junk'

    Note that if present, ``request.script`` is ignored by this function.
    If you need the original, absolute request URI, please use
    :func:`absolute_uri()`.


.. function:: absolute_uri(request)

    Create an absolute URI from an RGI *request* argument.

    >>> from collections import namedtuple
    >>> Request = namedtuple('Request', 'script path query')

    For example, when there is no query:

    >>> from degu.util import absolute_uri
    >>> request = Request(['foo'], ['bar', 'baz'], None)
    >>> absolute_uri(request)
    '/foo/bar/baz'

    And when there is a query:

    >>> request = Request(['foo'], ['bar', 'baz'], 'stuff=junk')
    >>> absolute_uri(request)
    '/foo/bar/baz?stuff=junk'

    Note that in real-life scenarios this function probably wont be used as
    often as :func:`relative_uri()` because RGI application should generally be
    abstracted from their exact mount point within a REST API.



.. _`wsgiref.util`: https://docs.python.org/3/library/wsgiref.html#module-wsgiref.util
.. _`Degu`: https://launchpad.net/degu
.. _`WSGI`: https://www.python.org/dev/peps/pep-3333/
