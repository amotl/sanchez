Features
========


Network sniffing and HTTP decoding
----------------------------------

For raw packet capturing, sanchez uses libnids [1], which in turn uses libpcap [2] and libnet [3].
For HTTP message decoding, dpkt [4] - a python packet creation / parsing library, gets used.
More highlevel decoding support gets lifted by the Python standard library.
All credits to the authors of these libs, we are standing on the shoulders of giants.

 - Captures network traffic using the underlying pcap library by applying a BPF filter,
   while this is encapsulated by libnids:

   Libnids is an implementation of an E-component of Network Intrusion Detection System.
   It emulates the IP stack of Linux 2.0.x. Libnids offers IP defragmentation, TCP stream
   assembly and TCP port scan detection.

 - Decodes HTTP messages using `dpkt.http.Request` and `dpkt.http.Response`


HTTP message decoding / display
-------------------------------

 - Dumps HTTP header information (optionally formatted and/or filtered)
 - Decodes text/json payloads
 - Plugins to add additional custom decoding steps



[1] http://libnids.sourceforge.net/
[2] http://www.tcpdump.org/release/
[3] http://www.packetfactory.net/libnet
[4] http://code.google.com/p/dpkt/
