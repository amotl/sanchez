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

def tcp_stream_handler(tcp):

    print "tcps -", str(tcp.addr), " state:", tcp.nids_state
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        print tcp.addr
        if True or dport in (80, 8000, 8080, 8181):
            print "collecting..."
            tcp.client.collect = 1
            tcp.server.collect = 1

    elif tcp.nids_state == nids.NIDS_DATA:
        # keep all of the stream's new data
        tcp.discard(0)

    elif tcp.nids_state in TCP_END_STATES:
        print "addr:", tcp.addr
        print "To server:"
        print tcp.server.data[:tcp.server.count] # WARNING - may be binary
        print "To client:"
        print tcp.client.data[:tcp.client.count] # WARNING - as above


# reassembles TCP flows before decoding HTTP
def decode_http(ip, conn):

    if type(ip) is types.StringType:
        print "ERROR: Could not decode ip packet"
        #print "string:", ip
        return

    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return

    tcp = ip.data

    tupl = (ip.src, ip.dst, tcp.sport, tcp.dport)
    #print tupl, tcp_flags(tcp.flags)

    # Ensure these are in order! TODO change to a defaultdict
    if tupl in conn:
        conn[tupl] = conn[tupl] + tcp.data
    else:
        conn[tupl] = tcp.data

    # TODO Check if it is a FIN, if so end the connection

    # Try and parse what we have
    try:
        stream = conn[tupl]
        http = None
        request = False
        response = False
        if stream[:4] == 'HTTP':
            http = dpkt.http.Response(stream)
            response = True
            #print http.status
            #print http.body
        else:
            http = dpkt.http.Request(stream)
            request = True
            #print http.method, http.uri

        #print tupl
        if http:
            #print tupl, tcp_flags(tcp.flags)


            # filter
            #print "ct:", http.headers.get('content-type', '').lower()
            output = False
            if request and 'json' in http.headers.get('accept', '').lower():
                output = True
            elif response and 'json' in http.headers.get('content-type', '').lower():
                output = True
            if not output:
                return


            # format message header
            ip_source = decode_ip(ip.src)
            ip_target = decode_ip(ip.dst)
            #print "source:", ip_source
            #print "target:", ip_target
            direction = '-'
            if request:
                direction = '->'
                conversation_header = 'REQUEST:  %s:%s %s %s:%s' % (ip_source, tcp.sport, direction, ip_target, tcp.dport)
            elif response:
                direction = '<-'
                conversation_header = 'RESPONSE: %s:%s %s %s:%s' % (ip_target, tcp.dport, direction, ip_source, tcp.sport)


            # output message header
            ansi.echo("blue bold underline")
            print "%s [%s]" % (conversation_header, tcp_flags(tcp.flags))
            ansi.echo()
            #print http


            # output/decode details
            if request:

                #print '%s %s %s/%s' % (http.method, http.uri, http.__proto, http.version)
                print http

            elif response:

                if int(http.status) < 400:
                    ansi.echo("green")
                else:
                    ansi.echo("red")
                print '%s/%s %s %s' % ('HTTP', http.version, http.status, http.reason)
                ansi.echo()
                print http.pack_hdr()

                body = http.body
                if 'gzip' in http.headers.get('content-encoding', ''):
                    import StringIO
                    import gzip
                    gzipper = gzip.GzipFile(fileobj = StringIO.StringIO(body))
                    body = gzipper.read()

                if 'json' in http.headers.get('content-type', '').lower():
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


            print


        # If we reached this part an exception hasn't been thrown
        stream = stream[len(http):]
        if len(stream) == 0:
            del conn[tupl]
        else:
            conn[tupl] = stream
    except dpkt.UnpackError, e:
        print "UnpackError:", e
        pass

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

    #nids.param("pcap_filter", "tcp and port 8181")      # bpf restrict to TCP only, note
                                                        # libnids caution about fragments
    nids.chksum_ctl([('0.0.0.0/0', False)])             # disable checksumming
    #nids.param("scan_num_hosts", 0)                    # disable portscan detection

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
    nids.param('pcap_filter', '(port 8181 or port 8080)')

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
