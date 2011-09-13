# -*- coding: utf-8 -*-

# basic blueprint from pynids Example [$Id: Example,v 1.3 2005/01/27 04:53:45 mjp Exp $]
# http://jon.oberheide.org/pynids/

import nids
from multiprocessing import Process
from pprint import pprint

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
        Process.__init__(self)

    def run(self):
        """
        """

        print "network sniffer process started"

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
            print
            print "-" * 42
            print list(tcp.addr), tcp.nids_state
            print "server: count={0}, count_new={1}, offset={2}".format(tcp.server.count, tcp.server.count_new, tcp.server.offset)
            print "client: count={0}, count_new={1}, offset={2}".format(tcp.client.count, tcp.client.count_new, tcp.client.offset)
            #print "request:\n", "'%s'" % request_raw
            #print "response:\n", "'%s'" % response_raw

            def dump(bucket):
                if bucket.count_new:
                    start = bucket.count - bucket.count_new
                    payload = bucket.data[start:bucket.count]
                    return payload

            print "request:\n", "'%s'" % dump(tcp.server)
            print "response:\n", "'%s'" % dump(tcp.client)

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
