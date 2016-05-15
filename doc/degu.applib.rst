:mod:`degu.applib` --- Library of RGI components
================================================

.. module:: degu.applib
   :synopsis: Library of RGI applications and middleware


:class:`RouterApp`
-------------------

.. class:: RouterApp(appmap)

    Generic RGI routing middleware.

    >>> def foo_app(session, request, api):
    ...     return (200, 'OK', {}, b'foo')
    ... 
    >>> def bar_app(session, request, api):
    ...     return (200, 'OK', {}, b'bar')
    ...
    >>> from degu.applib import RouterApp
    >>> router = RouterApp({'foo': foo_app, 'bar': bar_app})

    .. attribute:: appmap

        The *appmap* argument passed to the constructor.

    .. method:: __call__(session, request, api)

        RGI callable.


