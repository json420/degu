Degu
====

`Degu`_ is an embedded HTTP server and client library for Python3. It's well
suited for implementing REST APIs for device-to-device communication on the
local network.

.. warning::

    The Degu API is **not yet stable!**  Even the API documented here is still
    subject to change, although hopefully only subtle changes.

Degu includes:

    *   **A lightweight HTTP server** that's easy to embed within applications

    *   **A matching HTTP client** carefully designed to harmonize with the
        server

    *   **Stream-friendly IO abstractions** used by both the server and client
        for HTTP request and response bodies

Degu server applications are implemented according to the :doc:`rgi` (RGI),
which is very much in the spirit of `WSGI`_ but does not attempt to be
compatible with `CGI`_, nor necessarily to be compatible with any existing HTTP
servers.

Some noteworthy Degu features:

    *   Degu fully exposes HTTP "chunked" transfer-encoding semantics, including
        the optional per-chunk *extension*

    *   Degu provides access to full IPv6 address semantics, including the
        *scopeid* needed for IPv6 link-local addresses

    *   Degu transparently supports ``AF_INET``, ``AF_INET6``, and ``AF_UNIX``,
        all via a single *address* argument used uniformly by the server and
        client

    *   Degu provides a safe and opinionated API for using TLSv1.2, with a
        particular focus on using client certificates to authenticate incoming
        TCP connections

Degu is being developed as part of the `Novacut`_ project. Packages are
available for `Ubuntu`_ in the `Novacut Stable Releases PPA`_ and the `Novacut
Daily Builds PPA`_.

If you have questions or need help getting started with Degu, please stop by the
`#novacut`_ IRC channel on freenode.

Degu is licensed `LGPLv3+`_, and requires `Python 3.4`_ or newer.

Contents:

.. toctree::
    :maxdepth: 3

    install
    tutorial
    rgi
    degu
    degu.server
    degu.client
    degu.util
    degu.rgi
    degu.misc
    degu.base
    security
    changelog



.. _`Degu`: https://launchpad.net/degu
.. _`http.client`: https://docs.python.org/3/library/http.client.html
.. _`WSGI`: http://www.python.org/dev/peps/pep-3333/
.. _`CGI`: http://en.wikipedia.org/wiki/Common_Gateway_Interface

.. _`LGPLv3+`: http://www.gnu.org/licenses/lgpl-3.0.html
.. _`Novacut`: https://wiki.ubuntu.com/Novacut
.. _`Novacut Stable Releases PPA`: https://launchpad.net/~novacut/+archive/stable
.. _`Novacut Daily Builds PPA`: https://launchpad.net/~novacut/+archive/daily
.. _`#novacut`: http://webchat.freenode.net/?channels=novacut
.. _`Ubuntu`: http://www.ubuntu.com/
.. _`Python 3.4`: https://docs.python.org/3/

