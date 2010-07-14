# -*- coding: utf-8 -*-

# basic blueprint from pynids Example [$Id: Example,v 1.3 2005/01/27 04:53:45 mjp Exp $]
# http://jon.oberheide.org/pynids/

import nids
from multiprocessing import Process

TCP_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class Sniffer(Process):

    def __init__ (self, pipe, interface_name, bpf_filter):
        self.pipe = pipe
        self.interface_name = interface_name
        self.bpf_filter = bpf_filter
        Process.__init__(self)

    def run(self):

        print "network sniffer process started"
        #nids.param("pcap_filter", "tcp and port 8181")      # bpf restrict to TCP only, note
                                                            # libnids caution about fragments
        nids.chksum_ctl([('0.0.0.0/0', False)])             # disable checksumming
        nids.param("scan_num_hosts", 0)                     # disable portscan detection
        #nids.param("scan_delay", 60 * 1000)                 # disable portscan detection

        #nids.param("filename", sys.argv[1])                # read a pcap file?
        nids.param("device", self.interface_name)                   # read directly from device


        # apply BPF filter
        # see http://biot.com/capstats/bpf.html
        nids.param('pcap_filter', self.bpf_filter)

        nids.init()

        self.drop_root_privileges()

        nids.register_tcp(self.tcp_stream_handler)

        # Loop forever (network device), or until EOF (pcap file)
        # Note that an exception in the callback will break the loop!
        try:
            #print "nids.run"
            nids.run()
        except nids.error, e:
            print "nids/pcap error:", e
        except Exception, e:
            print "misc. exception (runtime error in user callback?):", e

        print "nids.stop"

    def drop_root_privileges(self):
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

    def tcp_stream_handler_1(self, tcp):
        try:
            self.tcp_stream_handler_impl(tcp)
        except Exception, e:
            print "Exception in sanchez.sniffer.tcp_stream_handler:", e

    def tcp_stream_handler(self, tcp):

        #print "tcps -", str(tcp.addr), " state:", tcp.nids_state

        if tcp.nids_state == nids.NIDS_JUST_EST:
            #print "get_pkt_ts-est:", nids.get_pkt_ts(), str(tcp.addr)
            # new to us, but do we care?
            ((src, sport), (dst, dport)) = tcp.addr
            #print tcp.addr
            if True or dport in (80, 8000, 8080, 8181):
                #print "collecting..."
                tcp.client.collect = 1
                tcp.server.collect = 1

        elif tcp.nids_state == nids.NIDS_DATA:
            #print "get_pkt_ts-dat:", nids.get_pkt_ts()
            # keep all of the stream's new data
            tcp.discard(0)

        elif tcp.nids_state in TCP_END_STATES:
            #print "get_pkt_ts-end:", nids.get_pkt_ts(), str(tcp.addr)
            #print dir(tcp)
            #print dir(tcp.server)
            #print dir(tcp.client)
            request_raw   = tcp.server.data[:tcp.server.count]
            response_raw  = tcp.client.data[:tcp.client.count]
            #print "queue.append"
            #print tcp.addr
            #print dir(tcp.addr)
            #entry = (((None, None), (None, None)), str(request_raw), str(response_raw))
            entry = (list(tcp.addr), str(request_raw), str(response_raw))
            self.pipe.send(entry)
