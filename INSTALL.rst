Installation guidelines for Mac OS X
====================================

Prerequisites
-------------

IS
--

wget http://jon.oberheide.org/pynids/downloads/pynids-0.6.1.tar.gz
tar -xzf pynids-0.6.1.tar.gz
cd pynids-0.6.1
python setup.py build
sudo python setup.py install

$ python
Python 2.6.5 (r265:79063, Jun 22 2010, 15:23:56)
[GCC 4.2.1 (Apple Inc. build 5646)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> import nids
>>> nids.__file__
'/opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/nidsmodule.so'


Notes
-----

We absolutely need v0.6.1, since this version brings an important feature which is required
for capturing traffic on Mac OS X' loopback interface (lo0):

    nids.chksum_ctl([('0.0.0.0/0', False)]) # disable checksumming

See Changelog
This pynids distribution is an updated version of Michael Pomraning's 0.5 series.
The 0.6 series brings updates to the bundled version of libnids (from 1.19 to 1.24),
checksum disabling, packet timestamps, pcap stats, and a variety of fixes.





WAS (old/deprecated)
--------------------


# A. install "pypcap" module
svn checkout http://pypcap.googlecode.com/svn/trunk/ pypcap-read-only
cd pypcap-read-only
python setup.py config
python setup.py build
sudo python setup.py install


# B. install "dpkt" module

# B.1) install to base python
wget http://dpkt.googlecode.com/files/dpkt-1.7-py2.6-macosx10.6.dmg
hdiutil attach dpkt-1.7-py2.6-macosx10.6.dmg
sudo installer -pkg /Volumes/dpkt-1.7-py2.6-macosx10.6/dpkt-1.7-py2.6-macosx10.6.mpkg -target /
hdiutil detach /Volumes/dpkt-1.7-py2.6-macosx10.6/

# B.2) install to custom python installation (e.g. coming from buildout):
sudo ln -s /Library/Python/2.6/site-packages/dpkt /opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/dpkt


# C. install "sanchez" to buildout (./bin/sanchez)
./bin/buildout -vvvvN


# D. install "sanchez" system-wide
sudo ./bin/buildout setup . install --script-dir=/usr/local/bin



Important notes
===============

# A. the required "pypcap" python module is from: http://code.google.com/p/pypcap/
     beware - this is *not* the pylibpcap module: http://pylibpcap.sourceforge.net/
     unfortunately, both would install as python module "pcap"

     so do *NOT*:
     `sudo port install py26-pylibpcap`
     (while sanchez might be made compatible in the future)


# B. install "dpkt" python module
     do *NOT*
     sudo port install py26-dpkt
     while this might work if it is linked to /opt/local/Library/Frameworks/Python.framework/Versions/2.6/lib/python2.6/site-packages/dpkt as well
