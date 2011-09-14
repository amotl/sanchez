# -*- coding: utf-8 -*-

import dpkt
from multiprocessing import Process
from sanchez.http import HttpConversation
#from http import HttpArtifact

class HttpCollector(Process):

    def __init__(self, sniffer_pipe, processing_chain_class, final_callback):
        self.pipe = sniffer_pipe
        self.chain_class = processing_chain_class
        self.callback = final_callback
        Process.__init__(self)

    def run(self):

        print "http collector started, pid=%s" % self.pid

        while True:

            artifact = self.pipe.recv()
            #print artifact
            #continue

            request = response = None
            try:
                if artifact.kind == 'request':
                    request = dpkt.http.Request(artifact.data)
                elif artifact.kind == 'response':
                    response = dpkt.http.Response(artifact.data)
            except dpkt.UnpackError, e:
                print "dpkt.UnpackError (problem decoding http):", e
                continue


            # container object to bundle ip peer information, request- and response objects
            conversation = HttpConversation(artifact.addr, request, response)

            chain = self.chain_class(conversation)
            if chain.process():
                self.callback(conversation)

    def run_conversation(self):

        print "http collector started"

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
