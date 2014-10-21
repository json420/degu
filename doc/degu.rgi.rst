:mod:`degu.rgi` --- RGI validation middleware
=============================================

.. module:: degu.rgi
   :synopsis: RGI validation middleware


The :class:`Validator` class is a middleware component for verifying that
servers, other middleware, and applications all comply with the :doc:`rgi`
specification.

A :class:`Validator` can be inserted between an RGI server and its top-level RGI
application, or can likewise be inserted between other RGI middleware and an
RGI application.

For example:

>>> from degu.rgi import Validator
>>> from degu.server import Server
>>> def my_app(session, request, bodies):
...     return (200, 'OK', {'x-msg': 'hello, world'}, None)
...
>>> app = Validator(my_app)
>>> server = Server(('127.0.0.1', 0), app)

It's possible (and sometimes quite useful) to add multiple :class:`Validator`
instances at different points in your RGI chain.  For example, you might do
something like this::

    server <=> validator1 <=> middleware <=> validator2 <=> application

Which in code would look like:

>>> class MyMiddleware:
...     def __init__(self, app):
...         self.app = app
...
...     def __call__(self, session, request, bodies):
...         return self.app(session, request, bodies)
...
...     def on_connect(self, session, sock):
...         if getattr(self.app, 'on_connect', None) is None:
...             return True
...         return self.app.on_connect(session, sock)
...
>>> app = Validator(MyMiddleware(Validator(my_app)))
>>> server = Server(('127.0.0.1', 0), app)


:class:`Validator` class
------------------------

.. class:: Validator(app)

    .. attribute:: app

        The *app* passed to the constructor.

    .. attribute:: _on_connect

        The *app.on_connect* attribute, or ``None`` if it lacks this attribute.

    .. method:: __call__(session, request, bodies)

        Request handler.

    .. method:: on_connect(session, sock)

        Connection handler.

