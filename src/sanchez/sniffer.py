# -*- coding: utf-8 -*-

# basic blueprint from pynids Example [$Id: Example,v 1.3 2005/01/27 04:53:45 mjp Exp $]
# http://jon.oberheide.org/pynids/

import nids
from multiprocessing import Process
from http import HttpArtifact
from pprint import pprint
from sanchez import config

TCP_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class Sniffer(Process):
    """
    Configure and bootstrap pcap-based packet sniffer
    - Does TCP stream reassembly using pynids
    - Sends results via pipe to parent process
      Each payload item is a triple:
            payload = (list(tcp.addr), str(request_raw), str(response_raw))

    Notes:
    ------
    Since pynids is not GIL aware, it will block all other Python "threads",
    so running this code out-of-process is essential.
    """

    def __init__ (self, pipe, interface_name, bpf_filter):
        self.pipe = pipe
        self.interface_name = interface_name
        self.bpf_filter = bpf_filter
        self.data = {}
        self.times = {}
        self.TRACE = False
        Process.__init__(self)

    def run(self):
        """
        """

        print "network sniffer started, pid=%s" % self.pid

        # apply BPF filter
        # see http://biot.com/capstats/bpf.html
        # bpf restrict to TCP only, note libnids caution about fragments
        nids.param('pcap_filter', self.bpf_filter)

        # various settings - may be essential
        nids.chksum_ctl([('0.0.0.0/0', False)])             # disable checksumming
        nids.param("scan_num_hosts", 0)                     # disable portscan detection
        #nids.param("scan_num_ports", 0)
        #nids.param("scan_delay", 0)

        nids.param("pcap_timeout", 64)
        nids.param("multiproc", True)
        nids.param("tcp_workarounds", True)

        #nids.param("filename", sys.argv[1])                # read a pcap file?
        nids.param("device", self.interface_name)           # read from network device

        # bootstrap
        nids.init()
        self.drop_root_privileges()
        nids.register_tcp(self.tcp_stream_handler)

        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        try:
            nids.run()
        except nids.error, e:
            print "nids/pcap error:", e
        except Exception, e:
            print "misc. exception (runtime error in user callback?):", e


    def tcp_stream_handler(self, tcp):
        """
        All your base are belong to us
        """

        #print "tcps -", str(tcp.addr), " state:", tcp.nids_state

        if tcp.nids_state == nids.NIDS_JUST_EST:
            #print "get_pkt_ts-est:", nids.get_pkt_ts(), str(tcp.addr)
            # new to us, but do we care?
            ((src, sport), (dst, dport)) = tcp.addr
            if dport in (80, 8000, 8080, 8181):
                #print "collecting..."
                tcp.client.collect = 1
                tcp.server.collect = 1
            return

        elif tcp.nids_state == nids.NIDS_DATA:
            #print "get_pkt_ts-dat:", nids.get_pkt_ts()
            # keep all of the stream's new data
            #tcp.discard(0)
            #print list(tcp.addr), tcp.nids_state
            #return
            #tcp.kill()
            tcp.discard(0)

            #request_raw   = tcp.server.data[tcp.server.offset:tcp.server.offset+tcp.server.count_new]
            #response_raw  = tcp.client.data[tcp.client.offset:tcp.client.offset+tcp.client.count_new]
            if self.TRACE:
                self.dump_header('DATA', tcp)
            #print "request:\n", "'%s'" % request_raw
            #print "response:\n", "'%s'" % response_raw

            """
            def dump(channel):
                if channel.count_new:
                    start = channel.count - channel.count_new
                    payload = channel.data[start:channel.count]
                    return payload
            print "request:\n", "'%s'" % dump(tcp.server)
            print "response:\n", "'%s'" % dump(tcp.client)
            """

            self.capture('request', tcp, tcp.server)
            self.capture('response', tcp, tcp.client)

            return


            #if request_raw:
            #    tcp.discard(len(request_raw))
            #if response_raw:
            #    tcp.discard(len(response_raw))
            print
            print "==============================================="
            pprint(self.data)

            if response_raw and self.data.has_key(tcp.addr):
                print "---------- SEEN REQUEST"
                print list(tcp.addr), tcp.nids_state
                req = self.data[tcp.addr]
                print "request:\n", "'%s'" % req
                print "response:\n", "'%s'" % response_raw
                del self.data[tcp.addr]
                tcp.discard(len(response_raw))
                return

            if request_raw:
                self.data[tcp.addr] = request_raw
                #tcp.discard(len(request_raw))
                #tcp.discard(0)
                tcp.discard(len(request_raw))
                return

            tcp.discard(0)

            return

            #tcp.discard(len(response_raw))
            #else:
            #payload = (list(tcp.addr), str(request_raw), str(response_raw))
            #self.pipe.send(payload)

        elif tcp.nids_state in TCP_END_STATES:

            if self.TRACE:
                self.dump_header('TERM', tcp)

            self.capture('request', tcp, tcp.server)
            self.capture('response', tcp, tcp.client)

            return

            #print "========= FINISH:", list(tcp.addr), tcp.nids_state
            #return
            #print "get_pkt_ts-end:", nids.get_pkt_ts(), str(tcp.addr)
            request_raw   = tcp.server.data[:tcp.server.count]
            response_raw  = tcp.client.data[:tcp.client.count]
            #print "request:", request_raw
            #print "response:", response_raw
            #"""
            # magic payload triple
            payload = (list(tcp.addr), str(request_raw), str(response_raw))
            #print list(tcp.addr), tcp.nids_state
            self.pipe.send(payload)
            #print dir(self.pipe)
            #"""
            tcp.client.collect = 0
            tcp.server.collect = 0


    def tcp_stream_handler_safe(self, tcp):
        try:
            self.tcp_stream_handler(tcp)
        except Exception, e:
            print "Exception in sanchez.sniffer.tcp_stream_handler:", e


    def capture(self, kind, tcp, channel):

        key = tuple([tcp.addr, kind])

        if channel.count_new > 0:
            if not self.times.has_key(key):
                self.times.setdefault(key, {})
                self.times[key]['begin'] = nids.get_pkt_ts()
            start = channel.count - channel.count_new
            payload = channel.data[start:channel.count]
            self.data.setdefault(key, '')
            self.data[key] += payload

            if config.http.response_check_keepalive \
                or config.sniffer.introspect_messages:
                payload = self.data[key]
                if self.is_message_complete(payload):
                    self.artifact_ready(tcp.addr, kind, key)

        elif self.data.has_key(key):
            if self.TRACE:
                self.dump_data(kind, key)
            self.artifact_ready(tcp.addr, kind, key)

    def artifact_ready(self, address, kind, key):
        self.times[key]['finish'] = nids.get_pkt_ts()
        #print "times:", self.times[key]
        #artifact = (key, self.data[key])
        artifact = HttpArtifact(address, kind, self.data[key], self.times[key]['begin'], self.times[key]['finish'])
        self.pipe.send(artifact)
        del self.data[key]
        del self.times[key]

    def is_message_complete(self, payload):
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
        if payload.startswith('HTTP/1.1 1') or payload.startswith('HTTP/1.1 204') or payload.startswith('HTTP/1.1 304'):
            return True

        else:

            def get_content_length_header():
                p1 = payload[:32768].lower().find('content-length: ')
                if p1 != -1:
                    p2 = payload[p1:32768].find('\r\n')
                    if p2 != -1:
                        fragment = payload[p1:p1+p2]
                        content_length_str = fragment.lower().replace('content-length: ', '')
                        content_length = int(content_length_str)
                        return content_length

            def get_content_length_real():
                p1 = payload.find('\r\n\r\n')
                if p1 != -1:
                    content_length = len(payload[p1+4:])
                    return content_length

            #print get_content_length_header(), get_content_length_real()
            header_length = get_content_length_header()
            real_length = get_content_length_real()
            if header_length != 0 and header_length is not None and header_length == real_length:
                return True

    def dump_get_separator(self, label, char='-'):
        return '-' * 21 + ' ' + label + ' ' + '-' * 21

    def dump_header(self, label, tcp):
        print
        print self.dump_get_separator(label, '-')
        print list(tcp.addr), tcp.nids_state
        print "server: count={0}, count_new={1}, offset={2}".format(tcp.server.count, tcp.server.count_new, tcp.server.offset)
        print "client: count={0}, count_new={1}, offset={2}".format(tcp.client.count, tcp.client.count_new, tcp.client.offset)

    def dump_data(self, kind, key):
        print
        print self.dump_get_separator(kind, '=')
        print key, "\n", self.data[key]

    def drop_root_privileges(self):
        # TODO: check this out
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
