# -*- coding: utf-8 -*-

from sanchez import config

# ------------------------------------------
#  configuration settings
# ------------------------------------------

# the network device to listen on (e.g. en0, en1, lo0, eth0, ...)
config.interface_name = 'lo0'

# set BPF filter
# see http://biot.com/capstats/bpf.html
# this gets fed into pynids
config.bpf_filter = 'tcp and port 80'

# which kinds of http messages should be displayed?
# by now, this is a mix of request- and response http headers
# in other words: the filter implementation currently doesn't distinguish them
config.http.filter.accept.header = {'accept': 'json', 'content-type': 'json'}
