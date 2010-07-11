#!/usr/bin/env python
# -*- coding: utf-8 -*-

# basic blueprint from pynids Example [$Id: Example,v 1.3 2005/01/27 04:53:45 mjp Exp $]

import os, sys
import types
import nids
import dpkt

from sanchez.utils import ansi


def decode_ip(ip_bytes):
    octet_parts = []
    for byte in ip_bytes:
        octet_parts.append(str(ord(byte)))
    octet = '.'.join(octet_parts)
    return octet


TCP_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def tcp_stream_handler(tcp, *more):

    #print "tcps -", str(tcp.addr), " state:", tcp.nids_state

    #print "more:", more

    if tcp.nids_state == nids.NIDS_JUST_EST:
        print "get_pkt_ts-est:", nids.get_pkt_ts(), str(tcp.addr)
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        #print tcp.addr
        if True or dport in (80, 8000, 8080, 8181):
            print "collecting..."
            tcp.client.collect = 1
            tcp.server.collect = 1

    elif tcp.nids_state == nids.NIDS_DATA:
        #print "get_pkt_ts-dat:", nids.get_pkt_ts()
        # keep all of the stream's new data
        tcp.discard(0)

    elif tcp.nids_state in TCP_END_STATES:
        print "get_pkt_ts-end:", nids.get_pkt_ts(), str(tcp.addr)
        #print dir(tcp)
        #print dir(tcp.server)
        #print dir(tcp.client)
        request_raw   = tcp.server.data[:tcp.server.count]
        response_raw  = tcp.client.data[:tcp.client.count]
        #print dir(tcp.server)
        request_http = response_http = None
        try:
            request_http  = dpkt.http.Request(request_raw)
            response_http = dpkt.http.Response(response_raw)
        except dpkt.UnpackError, e:
            print "dpkt.UnpackError (problem decoding http):", e

        if not filter_accept(tcp.addr, request_http, response_http):
            return

        print_header(tcp.addr, request = True)
        #return

        print request_http
        print_header(tcp.addr, response = True)
        print_response(response_http)
        print


def filter_accept(tcp, request, response):
    return \
        'json' in request.headers.get('accept', '').lower() \
        or \
        'json' in response.headers.get('content-type', '').lower()


def print_header(addr, request = False, response = False):
    label = "UNKNOWN"
    direction = '-'
    ((source_ip, source_port), (target_ip, target_port)) = addr
    if request:
        label = "REQUEST: "
        direction = '->'
    elif response:
        label = "RESPONSE:"
        direction = '<-'
    conversation_header = '%s %s:%s %s %s:%s' % (label, source_ip, source_port, direction, target_ip, target_port)

    ansi.echo("blue bold underline")
    print conversation_header
    ansi.echo()


def print_response(response):

    if int(response.status) < 400:
        ansi.echo("green")
    else:
        ansi.echo("red")
    print '%s/%s %s %s' % ('HTTP', response.version, response.status, response.reason)
    ansi.echo()
    print response.pack_hdr()

    body = response.body
    if 'gzip' in response.headers.get('content-encoding', ''):
        import StringIO
        import gzip
        gzipper = gzip.GzipFile(fileobj = StringIO.StringIO(body))
        body = gzipper.read()

    if 'json' in response.headers.get('content-type', '').lower():
        try:
            import json
            decoded = json.loads(body)
            #from pprint import pprint
            #pprint(decoded)
            #pretty = json.dumps(decoded, sort_keys=True, indent=4)
            pretty = json.dumps(decoded, sort_keys=False, indent=4)
            ansi.echo("green Pretty:")
            ansi.echo()
            print pretty
            #ansi.echo("@50;40")
            #print pretty
            print

            ansi.echo("green Decoded:")
            ansi.echo()
            print "hello world!"

        except Exception, e:
            ansi.echo("red ERROR: Could not decode json (%s)" % e)
            ansi.echo()
            print "Raw body was:"
            print body

def drop_root_privileges():
    # TODO: frop root privileges
    """
    import pwd
    NOTROOT = "nobody"   # edit to taste
    print "dropping root privileges"
    #print pwd.getpwnam(NOTROOT)
    #(uid, gid) = pwd.getpwnam(NOTROOT)[2:4]
    uid = 99
    gid = 99
    #print uid, gid
    os.setgroups([gid,])
    os.setgid(gid)
    os.setuid(uid)
    if 0 in [os.getuid(), os.getgid()] + list(os.getgroups()):
        print "error - drop root, please!"
        sys.exit(1)
    """


def main():

    if len(sys.argv) == 1:
        print "ERROR: Please specify network interface to listen on (e.g. lo0, en0, en1, ...)"
        sys.exit(1)

    #nids.param("pcap_filter", "tcp and port 8181")      # bpf restrict to TCP only, note
                                                        # libnids caution about fragments
    nids.chksum_ctl([('0.0.0.0/0', False)])             # disable checksumming
    nids.param("scan_delay", 60 * 1000)                 # disable portscan detection
    nids.param("scan_num_hosts", 0)                     # disable portscan detection

    #nids.param("filename", sys.argv[1])                # read a pcap file?
    nids.param("device", sys.argv[1])                   # read directly from device


    # apply BPF filter
    # captures all IPv4 HTTP packets to and from port 80, i.e. only packets that
    # contain data, not, for example, SYN and FIN packets and ACK-only packets
    # see http://biot.com/capstats/bpf.html
    #pc.setfilter('tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    #pc.setfilter('host netfrag.org and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    #pc.setfilter('host 178.63.253.130 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    #pc.setfilter('(port 8181 or port 8080) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    nids.param('pcap_filter', 'tcp and (port 8181 or port 8080)')

    nids.init()

    drop_root_privileges()

    ansi.echo("@@ bold")
    ansi.echo("red")
    print "sanchez v0.01 listening..."
    ansi.echo()
    print

    nids.register_tcp(tcp_stream_handler)

    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error:", e
    except Exception, e:
        print "misc. exception (runtime error in user callback?):", e


if __name__ == '__main__':
    main()
