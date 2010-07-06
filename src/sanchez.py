#!/usr/bin/python
# -*- coding: utf-8 -*-

# http://biot.com/capstats/bpf.html
# http://code.google.com/p/pypcap/
# http://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
# http://bramp.net/blog/follow-http-stream-with-decompression

# http://bitbucket.org/fairoldi/snifferapp/src/c40ffbf883e2/decoderthread.py
# http://dound.com/2009/09/integrating-twisted-with-a-pcap-based-python-packet-sniffer/


import dpkt, pcap


# reassembles TCP flows before decoding HTTP
def decode_http(eth, conn):
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			return
	
		ip = eth.data
		if ip.p != dpkt.ip.IP_PROTO_TCP:
			return
	
		tcp = ip.data
	
		tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
		#print tupl, tcp_flags(tcp.flags)
	
		# Ensure these are in order! TODO change to a defaultdict
		if tupl in conn:
			conn[ tupl ] = conn[ tupl ] + tcp.data
		else:
			conn[ tupl ] = tcp.data
	
		# TODO Check if it is a FIN, if so end the connection
	
		# Try and parse what we have
		try:
			stream = conn[ tupl ]
			if stream[:4] == 'HTTP':
				http = dpkt.http.Response(stream)
				#print http.status
				#print http.body
			else:
				http = dpkt.http.Request(stream)
				#print http.method, http.uri
	
			print http
			print

			# If we reached this part an exception hasn't been thrown
			stream = stream[len(http):]
			if len(stream) == 0:
				del conn[ tupl ]
			else:
				conn[ tupl ] = stream
		except dpkt.UnpackError:
			pass



pc = pcap.pcap()

# apply BPF filter
# captures all IPv4 HTTP packets to and from port 80, i.e. only packets that 
# contain data, not, for example, SYN and FIN packets and ACK-only packets
pc.setfilter('tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')

conn = dict() # Connections with current buffer (for reassembling TCP flows)
for ts, pkt in pc:
    eth = dpkt.ethernet.Ethernet(pkt)
    decode_http(eth, conn)
