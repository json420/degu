Degu
====

`Degu`_ is an embedded HTTP server and client library for Python3. It's well
suited for implementing REST APIs for device-to-device communication on the
local network.

.. warning::

    The Degu API is **not yet stable!**  Even the API documented here is still
    subject to change, although hopefully only subtle changes.  However, please
    expect gratuitous and frequent breakage if you venture into any of the
    currently *undocumented* API :)

Degu includes:

    * **A lightweight HTTP server** that's easy to embed in desktop and mobile
      applications

    * **A low-level HTTP client** comparable to the `http.client`_ module in the
      Python3 standard library

    * **IO abstractions and a common parser** used by both the server and client

    * **Test fixtures** that make it easy to create throw-away Degu server
      instances for unit testing

Degu server applications are implemented according to the :doc:`rgi`, which is
very much in the spirit of `WSGI`_ but does not attempt to be compatible with
`CGI`_, nor to be compatible with any existing HTTP servers.

Degu is being developed as part of the `Novacut`_ project. Packages are
available for `Ubuntu`_ in the `Novacut Stable Releases PPA`_ and the `Novacut
Daily Builds PPA`_.

If you have questions or need help getting started with Degu, please stop by the
`#novacut`_ IRC channel on freenode.

Degu is licensed `LGPLv3+`_, and requires `Python 3.4`_ or newer.

`Microfiber`_ now uses Degu as its underlying HTTP client, and `Dmedia`_ now
uses Degu as its underlying HTTP server.

Contents:

.. toctree::
    :maxdepth: 2

    install
    tutorial
    rgi
    degu
    degu.server
    degu.client
    degu.base
    degu.misc
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
.. _`Microfiber`: https://launchpad.net/microfiber
.. _`Dmedia`: https://launchpad.net/dmedia
