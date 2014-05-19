:mod:`degu.base` --- parser and IO abstractions
===============================================

.. module:: degu.base
   :synopsis: common HTTP parser and IO abstractions

This module provides the low level HTTP parser and IO abstractions used by both
:mod:`degu.server` and :mod:`degu.client`.


Output abstractions
-------------------

.. autoclass:: Output

.. autoclass:: ChunkedOutput

.. autoclass:: FileOutput


Input abstractions
------------------

.. autoclass:: Input

.. autoclass:: ChunkedInput
