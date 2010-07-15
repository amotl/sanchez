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
from sanchez.http import HttpConversation, HttpFilter, HttpDumper, HttpResponseDecoder,\
    HttpRequestDecoder
from sanchez.utils import ansi

class Collector():

    def __init__(self, pipe):
        self.pipe = pipe

    def start(self):
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

            # container object
            conversation = HttpConversation(addr, request_http, response_http)

            # apply e.g. http header filter
            filter = HttpFilter(conversation)
            if not filter.accept():
                continue

            # request: decode post data, etc.
            decoder = HttpRequestDecoder(conversation)
            decoder.decode()

            # response: decode gzip, json, etc.
            decoder = HttpResponseDecoder(conversation)
            decoder.decode()


            # dump request- and response messages to stdout,
            # possibly enriched from intermediary decoder steps
            dumper = HttpDumper(conversation)

            dumper.print_header(request = True)
            dumper.print_request()

            dumper.print_header(response = True)
            dumper.print_response()


def main():

    if len(sys.argv) == 1:
        print "ERROR: Please specify network interface to listen on (e.g. lo0, en0, en1, ...)"
        sys.exit(1)

    # set interface name (e.g. en0, en1, lo0, eth0, ...)
    interface_name = sys.argv[1]

    # set BPF filter
    # see http://biot.com/capstats/bpf.html
    bpf_filter = 'tcp and (port 8181 or port 8080)'


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

    # start sniffer process (uses pynids for tcp stream reassembly)
    # connect it by Pipe
    parent_conn, child_conn = Pipe()
    sniffer = Sniffer(pipe=child_conn, interface_name=interface_name, bpf_filter=bpf_filter)
    atexit.register(sniffer.terminate)
    sniffer.start()

    # start collector
    collector = Collector(pipe=parent_conn)
    collector.start()

    # wait for sniffer to terminate
    sniffer.join()

if __name__ == '__main__':
    main()
