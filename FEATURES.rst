Features
========


HTTP sniffer
------------
 - Captures network traffice using the pcap library by applying a BPF filter
 - Does TCP flow reassembling the brute force way: Tries to decode 
   HTTP messages using dpkt.http.Request and dpkt.http.Response
 - Dumps HTTP header information
 - Decodes text/json payloads
