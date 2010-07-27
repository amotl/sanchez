#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import sys
import time
import types
import atexit
import pkg_resources
from multiprocessing import Pipe

from sanchez import config, __VERSION__
from sanchez.sniffer import Sniffer
from sanchez.tcp import HttpCollector
from sanchez.http import HttpDecoderChain, HttpDumper, HttpResponseDecoder
from sanchez.utils import ansi


CONFIG_PATH = os.path.join(os.environ['HOME'], '.sanchez')
CONFIG_FILE = os.path.join(CONFIG_PATH, 'config.py')


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print "ERROR: configuration file %s does not exist" % CONFIG_FILE
        sys.exit(1)
    sys.path.append(CONFIG_PATH)
    import config


def read_commandline_arguments():

    if '--help' in sys.argv:
        print """Synopsis:
    $ sudo nice -n -20 sanchez
    $ sudo nice -n -20 sanchez lo0
    See also configuration file ~/.sanchez/config.py
        """
        sys.exit()

    if len(sys.argv) == 2:
        config.interface_name = sys.argv[1]


def print_startup_header():
    ansi.echo("@@ bold")
    ansi.echo("red")
    print "sanchez v%s" % ".".join(str(n) for n in __VERSION__)
    ansi.echo("none config:     ", end = '')
    ansi.echo("green %s" % CONFIG_FILE)
    ansi.echo("none interface:  ", end = '')
    ansi.echo("green %s" % config.interface_name)
    ansi.echo("none bpf filter: ", end = '')
    ansi.echo("green %s" % config.bpf_filter)
    ansi.echo("none plugins:    ", end = '')
    ansi.echo("green", end = '')
    print ", ".join([plugin.__name__ for plugin in HttpResponseDecoder.plugins])
    ansi.echo()
    print


def boot():
    # start sniffer process (uses pynids for tcp stream reassembly)
    # connect it by Pipe
    parent_conn, child_conn = Pipe()
    sniffer = Sniffer(pipe=child_conn, interface_name=config.interface_name, bpf_filter=config.bpf_filter)
    atexit.register(sniffer.terminate)
    sniffer.start()

    # start collector
    collector = HttpCollector(sniffer_pipe           = parent_conn,
                              processing_chain_class = HttpDecoderChain,
                              final_callback         = http_dump_callback)
    collector.start()

    # wait for sniffer to terminate
    sniffer.join()


def http_dump_callback(conversation):
    # dump request- and response messages to stdout,
    # possibly enriched from intermediary decoder steps
    dumper = HttpDumper(conversation)

    dumper.print_header(request = True)
    dumper.print_request()

    dumper.print_header(response = True)
    dumper.print_response()


def register_plugins():
    ENTRYPOINT = 'sanchez.plugins.HttpResponseDecoder'

    for entry_point in pkg_resources.iter_entry_points(ENTRYPOINT):
        HttpResponseDecoder.plugin_register(entry_point.load())

def main():
    register_plugins()
    load_config()
    read_commandline_arguments()
    print_startup_header()
    boot()

if __name__ == '__main__':
    main()
