Installing on Ubuntu
====================

Degu packages are available for `Ubuntu`_ in the
`Novacut Stable Releases PPA`_ and the `Novacut Daily Builds PPA`_.

Installation is easy. First add either the stable PPA::

    sudo apt-add-repository ppa:novacut/stable
    sudo apt-get update

Or the daily PPA::

    sudo apt-add-repository ppa:novacut/daily
    sudo apt-get update
    
And then install the ``python3-degu`` package::

    sudo apt-get install python3-degu

Optionally install the ``python3-degu-doc`` package to have this
documentation available locally and offline::

    sudo apt-get install python3-degu-doc

After which the documentation can be browsed at:

    file:///usr/share/doc/python3-degu-doc/html/index.html

Note that if you add both the stable and the daily PPA, the versions in the
daily PPA will supersede the versions in the stable PPA.

Also see :doc:`bugs`.


.. _`Ubuntu`: http://www.ubuntu.com/
.. _`Novacut Stable Releases PPA`: https://launchpad.net/~novacut/+archive/stable
.. _`Novacut Daily Builds PPA`: https://launchpad.net/~novacut/+archive/daily

