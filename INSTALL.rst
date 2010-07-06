Installation guidelines for Mac OS X
====================================

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
