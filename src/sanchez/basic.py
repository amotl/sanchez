#!/usr/bin/env python
# -*- coding: utf-8 -*-

# basic blueprint from pynids Example [$Id: Example,v 1.3 2005/01/27 04:53:45 mjp Exp $]

import os, sys
import time
import types
import dpkt
from threading import Thread

from sanchez.sniffer import Sniffer, queue
from sanchez.utils import ansi


def decode_ip(ip_bytes):
    octet_parts = []
    for byte in ip_bytes:
        octet_parts.append(str(ord(byte)))
    octet = '.'.join(octet_parts)
    return octet


class Receiver(Thread):

    def __init__ (self):
        Thread.__init__(self)

    def run(self):

        #print "more:", more

        print "show_stream - init"

        while True:

            print "show_stream - run:", queue.qsize()

            #time.sleep(1)
            #if len(queue) == 0:
            #    continue

            #(addr, request_raw, response_raw) = queue.pop()
            (addr, request_raw, response_raw) = queue.get(True)
            print "got entry"
            print "addr:", addr
            print "request:", request_raw
            print "response:", response_raw
            continue

            #print dir(tcp.server)
            request_http = response_http = None
            try:
                request_http  = dpkt.http.Request(request_raw)
                response_http = dpkt.http.Response(response_raw)
            except dpkt.UnpackError, e:
                print "dpkt.UnpackError (problem decoding http):", e

            if not filter_accept(addr, request_http, response_http):
                return

            print_header(addr, request = True)
            #return

            print request_http
            print_header(addr, response = True)
            print_response(response_http)
            print


def filter_accept(addr, request, response):
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



def main():

    if len(sys.argv) == 1:
        print "ERROR: Please specify network interface to listen on (e.g. lo0, en0, en1, ...)"
        sys.exit(1)

    sniffer = Sniffer(sys.argv[1], 'tcp and (port 8181 or port 8080)')

    ansi.echo("@@ bold")
    ansi.echo("red")
    print "sanchez v0.01 - standing on the shoulders of giants"
    ansi.echo()
    print

    sniffer.start()
    #show_stream()
    r = Receiver()
    r.start()

    #sniffer.start()


    print "finished!"

if __name__ == '__main__':
    main()
