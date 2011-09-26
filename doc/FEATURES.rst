Features
========


HTTP message decoding / display
-------------------------------

- Parsing modes
    - [x] simple: just dump the stream/flow
    - [o] conversational: with correlation of requests with their responses

- Decoding / Formatting
    - [x] application/x-www-form-urlencoded
    - [x] application/json (also groks "text/json")
    - [x] pretty printing of headers and decoded bodies

- Output modes
    - [x] Plain ASCII
        - [o] with and without ANSI coloring
    - [o] Static HTML
        - [o] just converted from ANSI
        - [o] with navigable anchors between conversation-index on top and conversation-details at the bottom
        - [o] by drilling into conversations with DHTML
    - [o] ncurses-based
        - [o] fields of list can be customized (e.g.: address, url, response code)
	- [o] Straight into database / pcap

- [o] Filtering by various criteria
    - [x] BPF filters
    - [o] totally by regex
    - [o] query by
        - [o] HTTP method
        - [o] request or response headers
        - [o] successful or failed conversations and similar "macros/shortcuts"
    - [o] RQL (Request Query Language)
        - URL
        - Header (e.g. User-Agent); e.g.::

            SELECT * FROM requests WHERE header_name="User-Agent" AND header_value="... MSIE 8.0 ...";

- [o] Interactive mode
	- [o] ncurses-based
    	- [o] display a list of http conversations which you can drill down into
		- [o] apply filters dynamically by moving around and pressing control keys
			- a: accept
			- r: reject
    - [/] Rich GUI => Okay, just use Wireshark!



- [o] Analysis
    - [o] HTTP spec verification: HTTP/1.0, HTTP/1.1
		- [o] Check for invalid headers
	- [o] Anomaly detection
		- [o] Check if delivered content matches the designated Content-Type header
		- [o] Check if length of delivered content matches the Content-Length header
		- [o] Verify that certain attributes inside JSON payloads match defined patterns
		- [o] Verify that all requests/responses carry certain headers with certain values (e.g. for CSRF protection)
    - [o] Forensics: save and load sessions (pcap)
	- [o] Comparisons: save, replay and compare sessions

- [o] Visualization
	- [o] Generate dot files from conversations

- [o] Plugins to add additional custom decoding steps et al.



Network sniffing and HTTP decoding
----------------------------------

For raw packet capturing, sanchez uses libnids [1], which in turn uses libpcap [2] and libnet [3].
For HTTP message decoding, dpkt [4] (a python packet creation / parsing library) gets used.
More highlevel decoding support gets lifted by the Python standard library.
All credits to the authors of these libs, we are really standing on the shoulders of giants.

- Captures network traffic using the underlying pcap library by applying a BPF filter,
  while this is encapsulated by libnids:

  Libnids is an implementation of an E-component of Network Intrusion Detection System.
  It emulates the IP stack of Linux 2.0.x. Libnids offers IP defragmentation, TCP stream
  assembly and TCP port scan detection.

- Decodes HTTP messages using `dpkt.http.Request` and `dpkt.http.Response`



Links
-----

| [1] http://libnids.sourceforge.net/
| [2] http://www.tcpdump.org/release/
| [3] http://www.packetfactory.net/libnet
| [4] http://code.google.com/p/dpkt/
