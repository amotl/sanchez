import curses
import atexit
from sanchez import config

class HttpSessionView(HttpUrlDumper):
    """
    A first attempt to a curses based ui.
    """

    window = None
    seqno = 0
    initialized = False

    def __init__(self, conversation):
        self.c = conversation
        if not HttpSessionView.initialized:
            self.initialize()
        
    def initialize(self):
        print "============= initialize ==========="
        HttpSessionView.initialized = True
        HttpSessionView.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        HttpSessionView.stdscr.keypad(1)
        atexit.register(HttpSessionView.bye)

        begin_x = 10 ; begin_y = 7
        height = 20 ; width = 80
        HttpSessionView.window = curses.newwin(height, width, begin_y, begin_x)
        
    def bye(self):
        print
        print
        print
        print "shutdown #1"
        print
        print
        print
        curses.nocbreak()
        HttpSessionView.stdscr.keypad(0)
        curses.echo()
        curses.endwin()
        print
        print
        print
        print "shutdown #2"
        print
        print
        print

    def dump(self):
        #print dir('')
        entry = self.c.request_line.ljust(50) + '      ' + self.format_response_status()
        
        HttpSessionView.window.addstr(HttpSessionView.seqno, 0, entry + ' #' + str(HttpSessionView.seqno))
                      #curses.A_REVERSE)
        HttpSessionView.seqno += 1
        HttpSessionView.window.refresh()
        
        #self.bye()
