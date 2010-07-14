#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os, sys
import time
import types
import dpkt
import shlex, subprocess
import atexit
from multiprocessing import Process, Pipe

from sanchez.sniffer import Sniffer
from sanchez.utils import ansi

class Receiver():

    def __init__(self, pipe):
        self.pipe = pipe

    def start(self):
        #print "starting data collector process"
        self.run()

    def run(self):

        print "data collector started"

        while True:

            (addr, request_raw, response_raw) = self.pipe.recv()
            request_http = response_http = None
            try:
                request_http  = dpkt.http.Request(request_raw)
                response_http = dpkt.http.Response(response_raw)
            except dpkt.UnpackError, e:
                print "dpkt.UnpackError (problem decoding http):", e
                continue

            if not filter_accept(addr, request_http, response_http):
                continue

            print_header(addr, request = True)
            print_request(request_http, response_http)

            print_header(addr, response = True)
            print_response(request_http, response_http)
            print

            #queue.task_done()


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

def print_request(request, response):
    print '%s %s %s/%s' % (request.method, request.uri, 'HTTP', request.version), "\t",
    if int(response.status) < 400:
        ansi.echo("green [%s %s]" % (response.status, response.reason))
    else:
        ansi.echo("red   [%s %s]" % (response.status, response.reason))
    ansi.echo()
    print request.pack_hdr()

    # pretty print post data
    if request.method == 'POST':
        ansi.echo("green POST data:")
        body = request.body
        post_parts = body.split('&')
        for part in post_parts:
            key, value = part.split('=', 1)
            print "%s: %s" % (key, value)


def print_response(request, response):

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
            pretty = json.dumps(decoded, sort_keys=True, indent=4)
            #pretty = json.dumps(decoded, sort_keys=False)
            ansi.echo("underline JSON - raw:")
            ansi.echo()
            print pretty
            #ansi.echo("@50;40")
            #print pretty
            print

        except Exception, e:
            ansi.echo("red ERROR: Could not decode json (%s)" % e)
            ansi.echo()
            print "Raw body was:"
            print body


def main():

    if len(sys.argv) == 1:
        print "ERROR: Please specify network interface to listen on (e.g. lo0, en0, en1, ...)"
        sys.exit(1)

    # set interface name (e.g. en0, en1, lo0, eth0, ...)
    interface_name = sys.argv[1]

    # set BPF filter
    # see http://biot.com/capstats/bpf.html
    bpf_filter = 'tcp and (port 8181 or port 8080)'

    # start sniffer process (uses pynids for tcp stream reassembly)
    # connect it by Pipe
    parent_conn, child_conn = Pipe()
    sniffer = Sniffer(pipe=child_conn, interface_name=interface_name, bpf_filter=bpf_filter)

    ansi.echo("@@ bold")
    ansi.echo("red")
    print "sanchez v0.02 - standing on the shoulders of giants"
    ansi.echo("none")
    ansi.echo("green")
    ansi.echo("none interface: ", end = '')
    ansi.echo("green %s" % interface_name, end = '')
    ansi.echo("none , bpf filter: ", end = '')
    ansi.echo("green %s" % bpf_filter)
    ansi.echo()
    print

    atexit.register(sniffer.terminate)

    sniffer.start()

    r = Receiver(pipe=parent_conn)
    r.start()

    sniffer.join()

if __name__ == '__main__':
    main()
