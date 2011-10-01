from operator import attrgetter
import curses
from sanchez.view.basic import HttpUrlDumper
from sanchez import config

class CursesSession(object):

    def __init__(self, callback):
        self.callback = callback
        self.setup()

    def setup(self):
        from curses.wrapper import wrapper
        def curses_started(screen):
            self.screen = screen
            self.callback(self)
        wrapper(curses_started)

class HttpTopEntry(object):
    def __init__(self, **data):
        self.__dict__.update(data)

class HttpTopView(object):

    def __init__(self, window):
        self.window = window
        self.entries = {}
        self.sort_attribute = 'request'
        if config.dumper.top.sortby:
            self.sort_attribute = config.dumper.top.sortby

    def add_entry(self, entry):

        key = entry.request
        if self.entries.has_key(key):
            entry_orig = self.entries[key]
            entry_orig.max = max(entry_orig.max, entry.duration)
            entry_orig.min = min(entry_orig.min, entry.duration)
            entry_orig.avg = (entry_orig.avg + entry.duration) / 2
        else:
            entry.max = entry.min = entry.avg = entry.duration
            self.entries[key] = entry

        self.redraw()

    def redraw(self):
        columns = ('request', 'response', 'avg', 'max', 'min')
        widths = (50, 15, 7, 7, 7)

        def format_line(record, header = False):
            #cells = ('#' + str(entry.seqno), entry.request.ljust(50), entry.response, entry.time_avg, entry.time_max, entry.time_min)
            cells = []
            for i, column in enumerate(columns):
                width = widths[i]
                if header:
                    cell = str(column)
                else:
                    cell = str(getattr(record, column))
                cell = cell.ljust(width)
                cells.append(cell)
            line = ''.join(cells)
            return line

        #import sys
        #sys.stderr.write(entries)
        self.window.clear()
        header = format_line(record = None, header = True)
        self.window.addstr(0, 0, header, curses.A_REVERSE)
        offset_y = 1
        entries = sorted(self.entries.values(), key=attrgetter(self.sort_attribute), reverse = True)
        for i, entry in enumerate(entries):
            line = format_line(entry)
            self.window.addstr(i + offset_y, 0, line)
        self.window.refresh()

class HttpTopDumper(HttpUrlDumper):
    """
    A first attempt to a curses based ui.
    """

    window = None
    seqno = 0
    initialized = False
    view = None

    def __init__(self, conversation, curses_session):
        self.c = conversation
        self.curses_session = curses_session
        window = self.curses_session.screen

        if not HttpTopDumper.view:
            HttpTopDumper.view = HttpTopView(window)

        #window.clearok(0)
        #if not HttpSessionView.initialized:
        #    self.initialize()
        
    def initialize(self):
        print "============= initialize ==========="
        HttpSessionView.initialized = True
        begin_x = 00 ; begin_y = 10
        height = 40 ; width = 80
        HttpSessionView.window = curses.newwin(height, width, begin_y, begin_x)
        
    def dump(self):
        
        entry = HttpTopEntry(
            request = self.c.request_line_short,
            response = self.format_response_status(),
            #duration = self.format_duration(),
            duration = self.c.duration,
            seqno = HttpTopDumper.seqno
        )
        HttpTopDumper.view.add_entry(entry)
        HttpTopDumper.seqno += 1
