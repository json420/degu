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
    particular RGI middleware applications that do request routing.

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


.. function:: build_relative_uri(request)

    Reconstruct a relative URI from an RGI *request* argument.

    This function is especially useful for reverse-proxy applications when
    building the URI used in their forwarded HTTP client request.

    For example, when there is no query:

    >>> from degu.util import build_relative_uri
    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': ''}
    >>> build_relative_uri(request)
    '/bar/baz'

    And when there is a query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> build_relative_uri(request)
    '/bar/baz?stuff=junk'

    Note that ``request['script']`` is ignored by this function.  If you need
    the original, absolute request URI, please use :func:`build_absolute_uri()`.


.. function:: build_absolute_uri(request)

    Reconstruct an absolute URI from an RGI *request* argument.

    For example, when there is no query:

    >>> from degu.util import build_absolute_uri
    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': ''}
    >>> build_absolute_uri(request)
    '/foo/bar/baz'

    And when there is a query:

    >>> request = {'script': ['foo'], 'path': ['bar', 'baz'], 'query': 'stuff=junk'}
    >>> build_absolute_uri(request)
    '/foo/bar/baz?stuff=junk'

    Note that in real-life scenarios this function probably wont be used as
    often as :func:`build_relative_uri()` because RGI application should
    generally be abstracted from their exact mount point within a REST API.



.. _`wsgiref.util`: https://docs.python.org/3/library/wsgiref.html#module-wsgiref.util
.. _`Degu`: https://launchpad.net/degu

