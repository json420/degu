:mod:`degu.jsonclient` --- High-level JSON client API
=====================================================

.. module:: degu.jsonclient
   :synopsis: Example high-level client API



:class:`JSONClient`
-------------------

.. class:: JSONClient(client, *script)

    High-level client API for for JSON lovin' REST APIs like CouchDB.

    The *client* argument can be a :class:`degu.client.Client`,
    a :class:`degu.client.SSLClient`, or an instance of any similar class
    implementing the required API.

    The *script* arguments provide the path components for the base URI from
    which all requests will be made.  It has the same meaning as the RGI
    ``request['script']``.

    .. attribute:: client

        The *client* argument provided to the constructor.

    .. attribute:: script

        The *script* arguments provided to the constructor.

    .. method:: connect(bodies=None)

        Create a new :class:`JSONConnection` instance.



:class:`JSONConnection`
-----------------------

.. class:: JSONConnection(conn, *script)

    High-level REST adapter for JSON lovin' REST APIs like CouchDB.

    The *conn* argument can be a :class:`degu.client.Connection`, or an instance
    of any similar class implementing the required API.

    The *script* arguments provide the path components for the base URI from
    which all requests will be made.  It has the same meaning as the RGI
    ``request['script']``.

    .. attribute:: conn

        The *conn* argument provided to the constructor.

    .. attribute:: script

        The *script* arguments provided to the constructor.

    .. attribute:: closed

        Property returns value of :attr:`degu.client.Connection.closed`.

    .. method:: close()

        Calls :meth:`degu.client.Connection.close()`.

    .. method:: request(method, headers, body, *path, **query)

    .. method:: json_request(method, headers, body, *path, **query)

    .. method:: post(obj, *path, **query)

    .. method:: put(obj, *path, **query)

    .. method:: get(*path, **query)

    .. method:: delete(*path, **query)

    .. method:: head(*path, **query)

    .. method:: put_att(attachment, *path, **query)

    .. method:: get_att(*path, **query)

