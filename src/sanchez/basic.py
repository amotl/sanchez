#!/usr/bin/env python
# -*- coding: utf-8 -*-

import types

import dpkt
import pcap

from sanchez.utils import ansi

def tcp_flags(flags):
    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + 'A'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'

    return ret


def decode_ip(ip_bytes):
    octet_parts = []
    for byte in ip_bytes:
        octet_parts.append(str(ord(byte)))
    octet = '.'.join(octet_parts)
    return octet


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


def main():

    #pc = pcap.pcap()
    pc = pcap.pcap('lo0')

    # apply BPF filter
    # captures all IPv4 HTTP packets to and from port 80, i.e. only packets that
    # contain data, not, for example, SYN and FIN packets and ACK-only packets
    # see http://biot.com/capstats/bpf.html
    #pc.setfilter('tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    #pc.setfilter('host netfrag.org and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    #pc.setfilter('host 178.63.253.130 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
    pc.setfilter('(port 8181 or port 8080) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')

    ansi.echo("@@ bold")
    ansi.echo("red")
    print "sanchez v0.01 listening..."
    ansi.echo()
    print

    conn = dict() # Connections with current buffer (for reassembling TCP flows)
    for ts, pkt in pc:

        #eth = dpkt.ethernet.Ethernet(pkt)
        #if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        #    print "ERROR: Could not decode ethernet packet (type=%s)" % hex(eth.type)
        #    return
        #ip = eth.data

        loop = dpkt.loopback.Loopback(pkt)
        ip = loop.data

        decode_http(ip, conn)


if __name__ == '__main__':
    main()
