# ansi2html Converts old BBS ANSI screens into HTML.
# by Leonard Richardson (http://www.crummy.com/)
# Public domain.
#
# It converts ANSI color codes into HTML styles.
# It converts CP437 characters (aka "IBM Extended ASCII") into HTML entities.
# It puts the whole thing in a preformatted HTML presentation.
#
# Thanks to:
#  http://www.fileformat.info/info/unicode/
#  http://search.cpan.org/~autrijus/HTML-FromANSI-1.01/
#  http://en.wikipedia.org/wiki/Code_page_437
#  http://en.wikipedia.org/wiki/ANSI_escape_code
#  http://home.claranet.de/xyzzy/ibm850.htm
#  http://www.crummy.com/source/software/download/bbs2ansi.pl

# First a dict mapping CP437 characters to numeric HTML entities and Unicode
# names.
# Characters in standard ASCII are not in this dict.
CP437_DICT = {
 '\x01' : ("&#x263A;", "WHITE SMILING FACE"),
 '\x02' : ("&#x263B;", "BLACK SMILING FACE"),
 '\x03' : ("&#x2665;", "BLACK HEART SUIT"),
 '\x04' : ("&#x2666;", "BLACK DIAMOND SUIT"),
 '\x05' : ("&#x2663;", "BLACK CLUB SUIT"),
 '\x06' : ("&#x2660;", "BLACK SPADE SUIT"),
 '\x07' : ("&#x2022;", "BULLET"),
 '\x08' : ("&#x25D8;", "INVERSE BULLET"),
 '\x09' : ("&#x25CB;", "WHITE CIRCLE"),
 '\x0a' : ("&#x25D9;", "INVERSE WHITE CIRCLE"),
 '\x0b' : ("&#x2642;", "MALE SIGN"),
 '\x0c' : ("&#x2640;", "FEMALE SIGN"),
 '\x0d' : ("&#x266A;", "EIGHTH NOTE"),
 '\x0e' : ("&#x266B;", "BEAMED EIGHTH NOTES"),
 '\x0f' : ("&#x263C;", "WHITE SUN WITH RAYS"),
 '\x10' : ("&#x25B8;", "BLACK RIGHT-POINTING SMALL TRIANGLE"),
 '\x11' : ("&#x25C2;", "BLACK LEFT-POINTING SMALL TRIANGLE"),
 '\x12' : ("&#x2195;", "UP DOWN ARROW"),
 '\x13' : ("&#x203C;", "DOUBLE EXCLAMATION MARK"),
 '\x14' : ("&#x00B6;", "PILCROW SIGN"),
 '\x15' : ("&#x00A7;", "SECTION SIGN"),
 '\x16' : ("&#x25AC;", "BLACK RECTANGLE"),
 '\x17' : ("&#x21A8;", "UP DOWN ARROW WITH BASE"),
 '\x18' : ("&#x2191;", "UPWARDS ARROW"),
 '\x19' : ("&#x2193;", "DOWNWARDS ARROW"),
 '\x1a' : ("&#x2192;", "RIGHTWARDS ARROW"),
 '\x1b' : ("&#x2190;", "LEFTWARDS ARROW"),
 '\x1c' : ("&#x221F;", "RIGHT ANGLE"),
 '\x1d' : ("&#x2194;", "LEFT RIGHT ARROW"),
 '\x1e' : ("&#x25B4;", "BLACK UP-POINTING SMALL TRIANGLE"),
 '\x1f' : ("&#x25BE;", "BLACK DOWN-POINTING SMALL TRIANGLE"),
 '\x21' : ("&#x0021;", "EXCLAMATION MARK"),
 '\x22' : ("&#x0022;", "QUOTATION MARK"),
 '\x23' : ("&#x0023;", "NUMBER SIGN"),
 '\x24' : ("&#x0024;", "DOLLAR SIGN"),
 '\x25' : ("&#x0025;", "PERCENT SIGN"),
 '\x26' : ("&#x0026;", "AMPERSAND"),
 '\x27' : ("&#x0027;", "APOSTROPHE"),
 '\x28' : ("&#x0028;", "LEFT PARENTHESIS"),
 '\x29' : ("&#x0029;", "RIGHT PARENTHESIS"),
 '\x2a' : ("&#x002A;", "ASTERISK"),
 '\x2b' : ("&#x002B;", "PLUS SIGN"),
 '\x2c' : ("&#x002C;", "COMMA"),
 '\x2d' : ("&#x002D;", "HYPHEN-MINUS"),
 '\x2e' : ("&#x002E;", "FULL STOP"),
 '\x2f' : ("&#x002F;", "SOLIDUS"),
 '\x7f' : ("&#x2302;", "HOUSE"),
 '\x80' : ("&#x00C7;", "LATIN CAPITAL LETTER C WITH CEDILLA"),
 '\x81' : ("&#x00FC;", "LATIN SMALL LETTER U WITH DIAERESIS"),
 '\x82' : ("&#x00E9;", "LATIN SMALL LETTER E WITH ACUTE"),
 '\x83' : ("&#x00E2;", "LATIN SMALL LETTER A WITH CIRCUMFLEX"),
 '\x84' : ("&#x00E4;", "LATIN SMALL LETTER A WITH DIAERESIS"),
 '\x85' : ("&#x00E0;", "LATIN SMALL LETTER A WITH GRAVE"),
 '\x86' : ("&#x00E5;", "LATIN SMALL LETTER A WITH RING ABOVE"),
 '\x87' : ("&#x00E7;", "LATIN SMALL LETTER C WITH CEDILLA"),
 '\x88' : ("&#x00EA;", "LATIN SMALL LETTER E WITH CIRCUMFLEX"),
 '\x89' : ("&#x00EB;", "LATIN SMALL LETTER E WITH DIAERESIS"),
 '\x8a' : ("&#x00E8;", "LATIN SMALL LETTER E WITH GRAVE"),
 '\x8b' : ("&#x00EF;", "LATIN SMALL LETTER I WITH DIAERESIS"),
 '\x8c' : ("&#x00EE;", "LATIN SMALL LETTER I WITH CIRCUMFLEX"),
 '\x8d' : ("&#x00EC;", "LATIN SMALL LETTER I WITH GRAVE"),
 '\x8e' : ("&#x00C4;", "LATIN CAPITAL LETTER A WITH DIAERESIS"),
 '\x8f' : ("&#x00C5;", "LATIN CAPITAL LETTER A WITH RING ABOVE"),
 '\x90' : ("&#x00C9;", "LATIN CAPITAL LETTER E WITH ACUTE"),
 '\x91' : ("&#x00E6;", "LATIN SMALL LETTER AE"),
 '\x92' : ("&#x00C6;", "LATIN CAPITAL LETTER AE"),
 '\x93' : ("&#x00F4;", "LATIN SMALL LETTER O WITH CIRCUMFLEX"),
 '\x94' : ("&#x00F6;", "LATIN SMALL LETTER O WITH DIAERESIS"),
 '\x95' : ("&#x00F2;", "LATIN SMALL LETTER O WITH GRAVE"),
 '\x96' : ("&#x00FB;", "LATIN SMALL LETTER U WITH CIRCUMFLEX"),
 '\x97' : ("&#x00F9;", "LATIN SMALL LETTER U WITH GRAVE"),
 '\x98' : ("&#x00FF;", "LATIN SMALL LETTER Y WITH DIAERESIS"),
 '\x99' : ("&#x00D6;", "LATIN CAPITAL LETTER O WITH DIAERESIS"),
 '\x9a' : ("&#x00DC;", "LATIN CAPITAL LETTER U WITH DIAERESIS"),
 '\x9b' : ("&#x00A2;", "CENT SIGN"),
 '\x9c' : ("&#x00A3;", "POUND SIGN"),
 '\x9d' : ("&#x00A5;", "YEN SIGN"),
 '\x9e' : ("&#x20A7;", "PESETA SIGN"),
 '\x9f' : ("&#x0192;", "LATIN SMALL LETTER F WITH HOOK"),
 '\xa0' : ("&#x00E1;", "LATIN SMALL LETTER A WITH ACUTE"),
 '\xa1' : ("&#x00ED;", "LATIN SMALL LETTER I WITH ACUTE"),
 '\xa2' : ("&#x00F3;", "LATIN SMALL LETTER O WITH ACUTE"),
 '\xa3' : ("&#x00FA;", "LATIN SMALL LETTER U WITH ACUTE"),
 '\xa4' : ("&#x00F1;", "LATIN SMALL LETTER N WITH TILDE"),
 '\xa5' : ("&#x00D1;", "LATIN CAPITAL LETTER N WITH TILDE"),
 '\xa6' : ("&#x00AA;", "FEMININE ORDINAL INDICATOR"),
 '\xa7' : ("&#x00BA;", "MASCULINE ORDINAL INDICATOR"),
 '\xa8' : ("&#x00BF;", "INVERTED QUESTION MARK"),
 '\xa9' : ("&#x2310;", "REVERSED NOT SIGN"),
 '\xaa' : ("&#x00AC;", "NOT SIGN"),
 '\xab' : ("&#x00BD;", "VULGAR FRACTION ONE HALF"),
 '\xac' : ("&#x00BC;", "VULGAR FRACTION ONE QUARTER"),
 '\xad' : ("&#x00A1;", "INVERTED EXCLAMATION MARK"),
 '\xae' : ("&#x00AB;", "LEFT-POINTING DOUBLE ANGLE QUOTATION MARK"),
 '\xaf' : ("&#x00BB;", "RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK"),
 '\xb0' : ("&#x2591;", "LIGHT SHADE"),
 '\xb1' : ("&#x2592;", "MEDIUM SHADE"),
 '\xb2' : ("&#x2593;", "DARK SHADE"),
 '\xb3' : ("&#x2502;", "BOX DRAWINGS LIGHT VERTICAL"),
 '\xb4' : ("&#x2524;", "BOX DRAWINGS LIGHT VERTICAL AND LEFT"),
 '\xb5' : ("&#x2561;", "BOX DRAWINGS VERTICAL SINGLE AND LEFT DOUBLE"),
 '\xb6' : ("&#x2562;", "BOX DRAWINGS VERTICAL DOUBLE AND LEFT SINGLE"),
 '\xb7' : ("&#x2556;", "BOX DRAWINGS DOWN DOUBLE AND LEFT SINGLE"),
 '\xb8' : ("&#x2555;", "BOX DRAWINGS DOWN SINGLE AND LEFT DOUBLE"),
 '\xb9' : ("&#x2563;", "BOX DRAWINGS DOUBLE VERTICAL AND LEFT"),
 '\xba' : ("&#x2551;", "BOX DRAWINGS DOUBLE VERTICAL"),
 '\xbb' : ("&#x2557;", "BOX DRAWINGS DOUBLE DOWN AND LEFT"),
 '\xbc' : ("&#x255D;", "BOX DRAWINGS DOUBLE UP AND LEFT"),
 '\xbd' : ("&#x255C;", "BOX DRAWINGS UP DOUBLE AND LEFT SINGLE"),
 '\xbe' : ("&#x255B;", "BOX DRAWINGS UP SINGLE AND LEFT DOUBLE"),
 '\xbf' : ("&#x2510;", "BOX DRAWINGS LIGHT DOWN AND LEFT"),
 '\xc0' : ("&#x2514;", "BOX DRAWINGS LIGHT UP AND RIGHT"),
 '\xc1' : ("&#x2534;", "BOX DRAWINGS LIGHT UP AND HORIZONTAL"),
 '\xc2' : ("&#x252C;", "BOX DRAWINGS LIGHT DOWN AND HORIZONTAL"),
 '\xc3' : ("&#x251C;", "BOX DRAWINGS LIGHT VERTICAL AND RIGHT"),
 '\xc4' : ("&#x2500;", "BOX DRAWINGS LIGHT HORIZONTAL"),
 '\xc5' : ("&#x253C;", "BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL"),
 '\xc6' : ("&#x255E;", "BOX DRAWINGS VERTICAL SINGLE AND RIGHT DOUBLE"),
 '\xc7' : ("&#x255F;", "BOX DRAWINGS VERTICAL DOUBLE AND RIGHT SINGLE"),
 '\xc8' : ("&#x255A;", "BOX DRAWINGS DOUBLE UP AND RIGHT"),
 '\xc9' : ("&#x2554;", "BOX DRAWINGS DOUBLE DOWN AND RIGHT"),
 '\xca' : ("&#x2569;", "BOX DRAWINGS DOUBLE UP AND HORIZONTAL"),
 '\xcb' : ("&#x2566;", "BOX DRAWINGS DOUBLE DOWN AND HORIZONTAL"),
 '\xcc' : ("&#x2560;", "BOX DRAWINGS DOUBLE VERTICAL AND RIGHT"),
 '\xcd' : ("&#x2550;", "BOX DRAWINGS DOUBLE HORIZONTAL"),
 '\xce' : ("&#x256C;", "BOX DRAWINGS DOUBLE VERTICAL AND HORIZONTAL"),
 '\xcf' : ("&#x2567;", "BOX DRAWINGS UP SINGLE AND HORIZONTAL DOUBLE"),
 '\xd0' : ("&#x2568;", "BOX DRAWINGS UP DOUBLE AND HORIZONTAL SINGLE"),
 '\xd1' : ("&#x2564;", "BOX DRAWINGS DOWN SINGLE AND HORIZONTAL DOUBLE"),
 '\xd2' : ("&#x2565;", "BOX DRAWINGS DOWN DOUBLE AND HORIZONTAL SINGLE"),
 '\xd3' : ("&#x2559;", "BOX DRAWINGS UP DOUBLE AND RIGHT SINGLE"),
 '\xd4' : ("&#x2558;", "BOX DRAWINGS UP SINGLE AND RIGHT DOUBLE"),
 '\xd5' : ("&#x2552;", "BOX DRAWINGS DOWN SINGLE AND RIGHT DOUBLE"),
 '\xd6' : ("&#x2553;", "BOX DRAWINGS DOWN DOUBLE AND RIGHT SINGLE"),
 '\xd7' : ("&#x256B;", "BOX DRAWINGS VERTICAL DOUBLE AND HORIZONTAL SINGLE"),
 '\xd8' : ("&#x256A;", "BOX DRAWINGS VERTICAL SINGLE AND HORIZONTAL DOUBLE"),
 '\xd9' : ("&#x2518;", "BOX DRAWINGS LIGHT UP AND LEFT"),
 '\xda' : ("&#x250C;", "BOX DRAWINGS LIGHT DOWN AND RIGHT"),
 '\xdb' : ("&#x2588;", "FULL BLOCK"),
 '\xdc' : ("&#x2584;", "LOWER HALF BLOCK"),
 '\xdd' : ("&#x258C;", "LEFT HALF BLOCK"),
 '\xde' : ("&#x2590;", "RIGHT HALF BLOCK"),
 '\xdf' : ("&#x2580;", "UPPER HALF BLOCK"),
 '\xe0' : ("&#x03B1;", "GREEK SMALL LETTER ALPHA"),
 '\xe1' : ("&#x03B2;", "GREEK SMALL LETTER BETA"),
 '\xe2' : ("&#x0393;", "GREEK CAPITAL LETTER GAMMA"),
 '\xe3' : ("&#x03C0;", "GREEK SMALL LETTER PI"),
 '\xe4' : ("&#x03A3;", "GREEK CAPITAL LETTER SIGMA"),
 '\xe5' : ("&#x03C3;", "GREEK SMALL LETTER SIGMA"),
 '\xe6' : ("&#x00B5;", "MICRO SIGN"),
 '\xe7' : ("&#x03C4;", "GREEK SMALL LETTER TAU"),
 '\xe8' : ("&#x03A6;", "GREEK CAPITAL LETTER PHI"),
 '\xe9' : ("&#x0398;", "GREEK CAPITAL LETTER THETA"),
 '\xea' : ("&#x03A9;", "GREEK CAPITAL LETTER OMEGA"),
 '\xeb' : ("&#x03B4;", "GREEK SMALL LETTER DELTA"),
 '\xec' : ("&#x221E;", "INFINITY"),
 '\xed' : ("&#x2205;", "EMPTY SET"),
 '\xee' : ("&#x2208;", "ELEMENT OF"),
 '\xef' : ("&#x2229;", "INTERSECTION"),
 '\xf0' : ("&#x2261;", "IDENTICAL TO"),
 '\xf1' : ("&#x00B1;", "PLUS-MINUS SIGN"),
 '\xf2' : ("&#x2265;", "GREATER-THAN OR EQUAL TO"),
 '\xf3' : ("&#x2264;", "LESS-THAN OR EQUAL TO"),
 '\xf4' : ("&#x2320;", "TOP HALF INTEGRAL"),
 '\xf5' : ("&#x2321;", "BOTTOM HALF INTEGRAL"),
 '\xf6' : ("&#x00F7;", "DIVISION SIGN"),
 '\xf7' : ("&#x2248;", "ALMOST EQUAL TO"),
 '\xf8' : ("&#x00B0;", "DEGREE SIGN"),
 '\xf9' : ("&#x2219;", "BULLET OPERATOR"),
 '\xfa' : ("&#x00B7;", "MIDDLE DOT"),
 '\xfb' : ("&#x221A;", "SQUARE ROOT"),
 '\xfc' : ("&#x207F;", "SUPERSCRIPT LATIN SMALL LETTER N"),
 '\xfd' : ("&#x00B2;", "SUPERSCRIPT TWO"),
 '\xfe' : ("&#x25AA;", "SMALL BLACK SQUARE"),
}

# FYI, common alternate choices for Unicode representations of CP437
# characters:
# 0x0f : ("&#x2736", "SIX POINTED BLACK STAR"),
# 0x10 : ("&#x25BA", "BLACK RIGHT-POINTING POINTER"),
# 0x11 : ("&#x25C4", "BLACK LEFT-POINTING POINTER"),
# 0x1e : ("&#x25B2", "BLACK UP-POINTING TRIANGLE"),
# 0x1f : ("&#x25BC", "BLACK DOWN-POINTING TRIANGLE"),
# 0xfe : ("&#x25A0", "BLACK SQUARE"),

import copy
import re
import sys

class ANSIDerivedHTML:

    ANSI_CODES = re.compile('\x1b\[(([0-9]+;)*)([0-9]+)?(.)')
    CP437_CHARS = re.compile('([\x01-\x09\x0b-\x0c\x0e-\x1f\x7f-\xfe])')
    # That regex includes a hack that avoids looking at newlines.

    DEFAULT_STYLE = { 'foreground' : 7,
                      'background' : 0,
                      'bold' : True,
                      'blink' : False }

    HTML_COLORS = ['black', 'darkred', 'darkgreen', '#8b8b00',
                   'darkblue', 'darkmagenta', 'darkcyan', 'gray']
    BOLD_HTML_COLORS = ['dimgray', 'red', 'green', 'yellow',
                        'blue', 'magenta', 'cyan', 'white']

    def __init__(self, text):
        self.ignored_commands = []
        self.style = copy.copy(self.DEFAULT_STYLE)
        self.unbalanced_span = False
        self.unbalanced_blink = False
        self.converted_text = self.to_html(text)

    def __str__(self):
        """Return the converted text."""
        return self.converted_text

    def to_html(self, text):
        """Replace CP437 characters and process ANSI codes."""
        # Get rid of anything between a cursor save and a cursor restore.
        text = re.compile("\x1b\[s.*?\x1b\[u", re.DOTALL).sub("", text)
        return self.htmlify_cp437(self.htmlify_ansi_color(text))

    def preformatted(self):
        """Return the converted text, preformatted for your convenience."""
        return ('<table style="%s"><tr><td><pre>%s</pre></td></tr></table>'
                % (self.css_style(self.DEFAULT_STYLE), self))
        #return '<pre>%s</pre>' % self

    def htmlify_cp437(self, text):
        """Replace special CP437 characters with HTML entity equivalents."""
        return self.CP437_CHARS.sub(self.process_cp437_char, text)

    def htmlify_ansi_color(self, text):
        """Replace ANSI color codes with styled <span> tags."""

        text = self.ANSI_CODES.sub(self.process_ansi_code, text)
        if self.unbalanced_span:
            text = text + '</span>'
            self.unbalanced_span = False

        if self.unbalanced_blink:
            text = text + '</blink>'
            self.unbalanced_blink = False
        return text

    def process_cp437_char(self, matchobj):
        char = matchobj.groups()[0]
        return CP437_DICT[char][0]

    def process_ansi_code(self, matchobj):
        result_parts = []
        groups = matchobj.groups()
        command = groups[-1]
        new_style = copy.copy(self.style)
        new_blink = False
        args = groups[0].split(';')[:-1]
        if groups[-2] is not None:
            args.append(groups[-2])
        args = [int(arg) for arg in args]
        if command == 'C': # Move cursor forward
            # Simulate by adding spaces.
            distance = groups[-2]
            return ' ' * int(distance)
        elif command == 'H': # Move cursor to arbitrary place
            # In most non-animated ANSIs this is used as a carriage return/
            # line feed. We'll change it to a newline.
            if args[-1] == 1:
                return '\n'
            else:
                sys.stderr.write("Couldn't handle cursor move to %s,%s\n"
                                 % tuple(args))
        elif command == 'm': # Change display properties
            for command in args:
                command = int(command)
                if command == 0:
                    new_style = copy.copy(self.DEFAULT_STYLE)
                elif command == 1:
                    new_style['bold'] = True
                elif command == 2:
                    new_style['bold'] = False
                elif command == 5 or command == 6:
                    new_style['blink'] = True
                elif command == 25:
                    new_style['blink'] = False
                elif command >= 30 and command < 39:
                    new_style['foreground'] = min(command-30, 7)
                elif command == 39:
                    new_style['foreground'] = self.DEFAULT_STYLE['foreground']
                elif command >= 40 and command < 49:
                    new_style['background'] = min(command-40, 7)
                elif command == 49:
                    new_style['background'] = self.DEFAULT_STYLE['background']
                else:
                    sys.stderr.write("Not sure how to handle SGR param "
                                     '"%s"\n' % command)
                    return ''
        else:
            sys.stderr.write("Not sure how to handle command %s\n"%
                             matchobj.group()[1:])
            self.ignored_commands.append(matchobj.group())
            return ''

        # If any attribute changed, close the <span> tag and start
        if (new_style != self.style):
            if self.unbalanced_span:
                result_parts.append('</span>')
                self.unbalanced_span = False
            result_parts.append('<span style="%s">'
                                % self.css_style(new_style))
            self.unbalanced_span = True


        # Update the style.
        self.style = new_style
        return ''.join(result_parts)

    def html_color(self, ansi_color, is_foreground, style=None):
        if style is None:
            style = self.style
        if style['bold'] and is_foreground:
            return self.BOLD_HTML_COLORS[ansi_color]
        else:
            return self.HTML_COLORS[ansi_color]

    def css_style(self, style=None):
        """A CSS style for the current color and blink settings."""
        if style is None:
            style = self.style
        blink_style = ''
        if style['blink']:
            blink_style = '; text-decoration: blink'
        return 'color:%s; background-color:%s%s' % (
            self.html_color(style['foreground'], True, style),
            self.html_color(style['background'], False, style),
            blink_style)

def self_test():
    # Character test
    char_lines = [[]]
    for i in range(1, 255):
        # Blah, special case for newline chars
        if i in [10, 13]:
            i = ord('X')
        char_lines[-1].append(chr(i))
        if i % 16 == 0 and i != 0:
            char_lines.append([])
    char_lines = [('\x1b[0m' + ''.join(line)) for line in char_lines]

    # Color test
    color_lines = [[]]
    for foreground in range(0,8):
        for background in range(0,8):
            color_lines[-1].append('\x1b[1;%s;%sm\x03' % (
                    foreground+30, background+40))
            color_lines[-1].append('\x1b[2m\x03')
        #Finish off with a blink demo
        color_lines[-1].append('\x1b[5m\x03')
        color_lines[-1].append('\x1b[0m')
        color_lines.append([])
    color_lines = [''.join(line) for line in color_lines]
    while len(color_lines) < len(char_lines):
        color_lines.append('')

    text = '\n'.join(['%s    %s' % (ch, co)
                       for ch, co in zip(char_lines, color_lines)])
    return ANSIDerivedHTML(text).preformatted()

for file in sys.argv:
    ansi = open(file).read()
    html_file = file + '.html'
    print "%s => %s" % (file, html_file)
    html = ANSIDerivedHTML(ansi)
    html_handle = open(html_file, 'w')
    html_handle.write(html.preformatted())
    html_handle.close()
