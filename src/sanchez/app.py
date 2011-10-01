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
from sanchez.http import HttpDecoderChain, HttpResponseDecoder
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

    #if len(sys.argv) == 2:
    #    config.interface_name = sys.argv[1]


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


curses_session = None
def boot():

    from monkey import patch_dpkt
    patch_dpkt()

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

    if config.http.dumper in ['top', 'session']:
        from sanchez.view.ui_curses import CursesSession
        def boot_real(csession):
            global curses_session
            curses_session = csession
            print_startup_header()
            collector.start()
        curses_session = CursesSession(callback = boot_real)
    else:
        print_startup_header()
        collector.start()

    # wait for sniffer to terminate
    #print "================ before join ================"
    sniffer.join()
    collector.join()


def http_dump_callback(conversation):
    """
    Dump request- and response messages to stdout,
    possibly enriched from intermediary decoder steps.
    """

    dumper = None

    # default dumper: ngrep++ mode
    if not config.http.dumper:
        config.http.dumper = 'detail'

    # choose different dumper by config
    if config.http.dumper == 'detail':
        from sanchez.view.basic import HttpDetailDumper
        dumper_class = HttpDetailDumper
    elif config.http.dumper == 'url':
        from sanchez.view.basic import HttpUrlDumper
        dumper_class = HttpUrlDumper
    elif config.http.dumper == 'top':
        from sanchez.view.ui_curses import HttpTopDumper
        dumper = HttpTopDumper(conversation, curses_session)
    elif config.http.dumper == 'session':
        from sanchez.view.ui_curses import HttpSessionView
        dumper = HttpSessionView(conversation, curses_session)

    # run it
    if not dumper:
        dumper = dumper_class(conversation)

    # run it
    dumper.dump()


def register_plugins():
    ENTRYPOINT = 'sanchez.plugins.HttpResponseDecoder'

    for entry_point in pkg_resources.iter_entry_points(ENTRYPOINT):
        HttpResponseDecoder.plugin_register(entry_point.load())

def main():
    register_plugins()
    load_config()
    read_commandline_arguments()
    #print_startup_header()
    boot()

if __name__ == '__main__':
    main()
