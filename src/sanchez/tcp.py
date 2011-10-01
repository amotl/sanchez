# -*- coding: utf-8 -*-

import dpkt
from multiprocessing import Process
from sanchez.http import HttpConversation
from sanchez import config
#from http import HttpArtifact
from sanchez.utils import ansi

class HttpCollector(Process):

    def __init__(self, sniffer_pipe, processing_chain_class, final_callback):
        self.pipe = sniffer_pipe
        self.chain_class = processing_chain_class
        self.callback = final_callback

        self.conversations = {}

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
                    request.time_begin = artifact.begin
                    request.time_finish = artifact.finish
                elif artifact.kind == 'response':
                    response = dpkt.http.Response(artifact.data)
                    response.time_begin = artifact.begin
                    response.time_finish = artifact.finish
            except dpkt.UnpackError, e:
                ansi.echo("red ERROR: dpkt.UnpackError (problem decoding http %s): %s" % (artifact.kind, e))
                continue


            # container object to bundle ip peer information, request- and response objects
            conversation = HttpConversation(artifact.addr, request, response)
            if config.collector.conversation.correlate:
                self.correlate_conversation(conversation)
            else:
                self.process_conversation(conversation)

    def correlate_conversation(self, half):
        #print (half.seqno, half.addr, half.request, half.response) #; return
        if half.request:
            self.conversations[half.addr] = half
        elif half.response:
            full = self.conversations.get(half.addr)
            if full:
                full.response = half.response
                if abs(full.seqno - half.seqno) > 1:
                    full.response.correlated = True
                del self.conversations[half.addr]
                self.process_conversation(full)
            else:
                ansi.echo("red WARNING: Correlator received the following response without having an associated request")
                self.process_conversation(half)

    def process_conversation(self, conversation):
        """
        Run HttpDecoderChain, then call back to user.
        """
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
