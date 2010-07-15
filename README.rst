Sanchez - the packet sniffer you have been looking for
======================================================


SYNOPSIS.rst


WARNING
-------

HANDLE WITH CARE ON PRODUCTION SYSTEMS:
This uses libnids, which emulates the TCP/IP stack of a 2.0.x linux kernel.

FROM libnids-1.24/MISC:
All NIDS are vulnerable to DOS attacks. Libnids uses efficient data
structures (i.e. hash tables) to minimize risk of CPU saturation. However, all
NIDS (including ones based on libnids) has to define some resources (most
notably, memory) limits. A determined attacker can attempt to make libnids use
up all of its memory, which can result in dropping some data. Libnids will
report such condition via its D-component interface.



FEATURES.rst

INSTALL.rst

LINKS.rst
