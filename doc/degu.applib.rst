:mod:`degu.applib` --- Library of RGI components
================================================

.. module:: degu.applib
   :synopsis: Library of RGI applications and middleware

.. versionadded:: 0.16

The goal of this module is to provide a number of pre-built RGI middleware and
leaf-application components for common scenarios.

.. warning::
    None of the classes in this module are yet API stable; use them at your
    own risk!

    These components might still undergo backward incompatible API changes, be
    renamed, or be removed entirely!



:class:`AllowedMethods`
-----------------------

.. class:: AllowedMethods(*methods)

    Decorator used to filter methods allow by a downstream RGI component.

    For example:

    >>> from degu.applib import AllowedMethods
    >>> @AllowedMethods('GET')
    ... def myapp(session, request, body):
    ...     return (200, 'OK', {}, b'hello, world')
    ...

    Each of the provided *methods* must be ``str`` instances in the set of
    currently allowed Degu HTTP methods::

        {'GET', 'HEAD', 'PUT', 'POST', 'DELETE'}

    .. versionadded:: 0.17

    .. method:: __call__(app)

        Callable (decorator) that returns a :class:`MethodFilter`.



:class:`MethodFilter`
---------------------

.. class:: MethodFilter(app, allowed_methods)

    RGI middleware to filter methods allowed by downstream RGI component.

    For example:

    >>> from degu.applib import AllowedMethods, MethodFilter
    >>> ro_methods = AllowedMethods('GET', 'HEAD')
    >>> def myapp(session, request, body):
    ...     data = b'hello, world'
    ...     headers = {'content-length': len(body)}
    ...     response_body = (None if request.method == 'HEAD' else data)
    ...     return (200, 'OK', headers, response_body)
    ...
    >>> method_filter = MethodFilter(myapp, ro_methods)

    The *app* argument must be the RGI callable which is called when the request
    is for an allowed HTTP method.

    The *allowed_methods* argument must be an :class:`AllowedMethods` instances
    specifying which methods will be passed down to the *app* callable.

    When a :class:`MethodFilter` instance is called with a
    :attr:`degu.server.Request.method` not in *allowed_methods*, a
    **405 Method Not Allowed** response is returned::

        (405, 'Method Not Allowed', {}, None)

    Otherwise the request is passed onto the :attr:`MethodFilter.app` callable
    provided to the constructor.

    .. versionadded:: 0.17

    .. attribute:: app

        The RGI callable passed to the constructor.

    .. attribute:: allowed_methods

        The :class:`AllowedMethods` instance passed to the constructor.

    .. method:: __call__(session, request, api)

        RGI callable.

        This method returns a ``(status,reason,headers,body)`` 4-tuple.



:class:`Router`
---------------

.. class:: Router(appmap)

    Generic RGI routing middleware.

    >>> def foo_app(session, request, api):
    ...     return (200, 'OK', {}, b'foo')
    ... 
    >>> def bar_app(session, request, api):
    ...     return (200, 'OK', {}, b'bar')
    ...
    >>> from degu.applib import Router
    >>> router = Router({'foo': foo_app, 'bar': bar_app})

    .. versionchanged:: 0.17

        This class was renamed from ``RouterApp`` to :class:`Router`.

    .. attribute:: appmap

        The *appmap* argument passed to the constructor.

    .. method:: __call__(session, request, api)

        RGI callable.

        This method returns a ``(status,reason,headers,body)`` 4-tuple.



:class:`Proxy`
--------------

.. class:: Proxy(client, key='conn')

    Generic RGI reverse-proxy application.

    .. versionchanged:: 0.17

        This class was renamed from ``ProxyApp`` to :class:`Proxy`.

    .. attribute:: client

        The *client* argument passed to the constructor.

    .. attribute:: key

        The *key* argument passed to the constructor.

    .. method:: __call__(session, request, api)

        RGI callable.

        This method returns a ``(status,reason,headers,body)`` 4-tuple.

