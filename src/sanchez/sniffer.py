# -*- coding: utf-8 -*-

from threading import Thread
#from collections import deque
from Queue import Queue
import nids


#queue = deque()
queue = Queue()


TCP_END_STATES = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

class Sniffer(Thread):

    def __init__ (self, interface_name, bpf_filter):
        Thread.__init__(self)
        self.interface_name = interface_name
        self.bpf_filter = bpf_filter

    def run(self):

        #nids.param("pcap_filter", "tcp and port 8181")      # bpf restrict to TCP only, note
                                                            # libnids caution about fragments
        nids.chksum_ctl([('0.0.0.0/0', False)])             # disable checksumming
        nids.param("scan_num_hosts", 0)                     # disable portscan detection
        #nids.param("scan_delay", 60 * 1000)                 # disable portscan detection

        #nids.param("filename", sys.argv[1])                # read a pcap file?
        nids.param("device", self.interface_name)                   # read directly from device


        # apply BPF filter
        # captures all IPv4 HTTP packets to and from port 80, i.e. only packets that
        # contain data, not, for example, SYN and FIN packets and ACK-only packets
        # see http://biot.com/capstats/bpf.html
        #pc.setfilter('tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
        #pc.setfilter('host netfrag.org and tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
        #pc.setfilter('host 178.63.253.130 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')
        #pc.setfilter('(port 8181 or port 8080) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)')

        #nids.param('pcap_filter', 'tcp and (port 8181 or port 8080)')
        #nids.param('pcap_filter', 'tcp and (port 18181)')
        nids.param('pcap_filter', self.bpf_filter)

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
            print "queue.append"
            entry = (tcp.addr, request_raw, response_raw)
            #queue.appendleft()
            queue.put(entry)

            #tcp.client.collect = 0
            #tcp.server.collect = 0

            #print entry
