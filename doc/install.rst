Installation
============

`Degu`_ packages are available for `Ubuntu`_ in the
`Novacut Stable Releases PPA`_ and the `Novacut Daily Builds PPA`_.

Install on Ubuntu
-----------------

Installation on Ubuntu is easy. First add either the stable PPA::

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



Source code
-----------

You can also download the source code tarball for each release `from
Launchpad`_.



bzr trunk
---------

Finally, can you grab the latest code from the `bzr trunk`_ branch like this::

    bzr checkout lp:degu

Or create your own branch for your own work like this::

    bzr branch lp:degu lp:~/degu/mybranch
    bzr checkout lp:~/degu/mybranch



Reporting bugs
--------------

The `degu Launchpad project`_ is where all Degu development is
coordinated, including bug tracking.

If you're using `Ubuntu`_ and have the ``python3-degu`` package installed,
the best way to file a bug is to open a terminal and run::

    ubuntu-bug python3-degu

This will automatically attach useful information to the bug report, which
can greatly help in diagnosing the problem.

Otherwise, please file a bug directly `through the web UI`_.



.. _`Degu`: https://launchpad.net/degu
.. _`Ubuntu`: http://www.ubuntu.com/
.. _`Novacut Stable Releases PPA`: https://launchpad.net/~novacut/+archive/stable
.. _`Novacut Daily Builds PPA`: https://launchpad.net/~novacut/+archive/daily
.. _`from Launchpad`: https://launchpad.net/degu/+download
.. _`bzr trunk`: https://code.launchpad.net/~dmedia/degu/trunk
.. _`degu Launchpad project`: https://launchpad.net/degu
.. _`through the web UI`: https://bugs.launchpad.net/degu

