# -*- coding: utf-8 -*-

import dpkt
from sanchez.http import HttpConversation

class HttpCollector(object):

    def __init__(self, sniffer_pipe, processing_chain_class, final_callback):
        self.pipe = sniffer_pipe
        self.chain_class = processing_chain_class
        self.callback = final_callback

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

            # container object to bundle ip peer information, request- and response objects
            conversation = HttpConversation(addr, request_http, response_http)

            chain = self.chain_class(conversation)
            if chain.process():
                self.callback(conversation)
