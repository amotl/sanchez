Installation guidelines for Mac OS X
====================================

Please complement for other os types....

::

	sudo ln -s ~/dev/tools/sanchez/bin/sanchez /usr/local/bin/sanchez


Prerequisites
=============

libnet
------
::

    sudo port install libnet11

pynids
------
::

    wget http://jon.oberheide.org/pynids/downloads/pynids-0.6.1.tar.gz
    tar -xzf pynids-0.6.1.tar.gz
    cd pynids-0.6.1
    python setup.py build
    sudo python setup.py install

    $ python
    >>> import nids
    >>> nids.__file__
    '/opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/nidsmodule.so'


dpkt
----

- install to base python::

   wget http://dpkt.googlecode.com/files/dpkt-1.7-py2.6-macosx10.6.dmg
   hdiutil attach dpkt-1.7-py2.6-macosx10.6.dmg
   sudo installer -pkg /Volumes/dpkt-1.7-py2.6-macosx10.6/dpkt-1.7-py2.6-macosx10.6.mpkg -target /
   hdiutil detach /Volumes/dpkt-1.7-py2.6-macosx10.6/


- could work as well::

   sudo port install py26-dpkt


- link to custom (buildout) python installation::

   sudo ln -s /Library/Python/2.6/site-packages/dpkt /opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/dpkt

   $ python
   >>> import dpkt
   >>> dpkt.__file__
   '/opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/dpkt/__init__.pyc'


sanchez
=======

variants
--------

- install "sanchez" to buildout (./bin/sanchez)::

   ./bin/buildout -vvvvN


- install "sanchez" entrypoint system-wide; will copy eggs to the system::

   sudo ./bin/buildout setup . install --script-dir=/usr/local/bin


- development mode: install "sanchez" entrypoint system-wide, while leaving sources in this tree::

   sudo ./bin/buildout setup . develop --script-dir=/usr/local/bin


variant c) is recommended for easy hacking


Configuration
-------------

Please deploy to `~/.sanchez/config.py`:

`config.py <config.py>`_




Notes
=====

We require pynids v0.6.1, since this version brings an important feature
which enables capturing traffic on Mac OS X' loopback interface (lo0)::

    nids.chksum_ctl([('0.0.0.0/0', False)])     # disable checksumming

See Changelog
This pynids distribution is an updated version of Michael Pomraning's 0.5 series.
The 0.6 series brings updates to the bundled version of libnids (from 1.19 to 1.24),
checksum disabling, packet timestamps, pcap stats, and a variety of fixes.
