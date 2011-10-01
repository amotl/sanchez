from sanchez.http import HttpHeaderFilterStep
from sanchez.utils import ansi
from sanchez import config

class HttpDetailDumper(object):
    """
    dumps details of http messages to console
    uses ansi control codes for shiny colors ;]
    as with almost all ui stuff, this is a mess
    """

    def __init__(self, conversation):
        self.c = conversation

    def dump(self):

        if self.c.request is not None and self.c.response is not None:
            print
            print "=" * 79
            print

        if self.c.request is not None:
            self.print_section_header(request = True)
            self.print_request()
            print

        if self.c.response is not None:
            more = ''
            if self.c.response.correlated:
                more = '[correlated]'
            self.print_section_header(response = True, more = more)
            self.print_response()
            print


    def print_section_header(self, request = False, response = False, more = ''):
        label = "UNKNOWN"
        direction = '-'
        ((source_ip, source_port), (target_ip, target_port)) = self.c.addr
        if request:
            label = "REQUEST: "
            direction = '->'
        elif response:
            label = "RESPONSE:"
            direction = '<-'
        conversation_header = '%s %s:%s %s %s:%s' % (label, source_ip, source_port, direction, target_ip, target_port)

        ansi.echo("blue bold underline")
        print conversation_header,
        ansi.echo('none')
        if more:
            ansi.echo('yellow   ' + more)
        else:
            print

    def print_message_header(self, message):
        ansi.echo()
        if config.http.view.headers.pretty:
            print message.pack_hdr_pretty()
        else:
            print message.pack_hdr()

    def print_message_steps(self, message):
        if message.steps:
            ansi.echo('yellow [' + ', '.join(message.steps) + ']')
            ansi.echo('none')

    def print_request_line(self):
        print self.c.request_line, "\t", self.format_response_status(with_ansi = True), '\t', self.format_duration(with_ansi = True)

    def format_response_status(self, with_ansi = False):
        # print status of correlated response on top, if available
        # TODO: refactor to separate method "print_conversation_header"
        result = ''
        response = self.c.response
        if response is not None:
            result = "[%s %s]" % (response.status, response.reason)
            if with_ansi:
                if int(response.status) < 400:
                    status_color = 'green'
                else:
                    status_color = 'red'
                result = ansi.get("%s %s" % (status_color, result), end = '') + ansi.get('none', end = '')
        return result

    def format_duration(self, with_ansi = False):
        try:
            duration_str = (str(self.c.duration) + 'ms').rjust(6)
            if with_ansi:
                return ansi.get('yellow') + duration_str + ansi.get('none')
            else:
                return duration_str
        except Exception as ex:
            ansi.echo("red WARNING: Could not compute duration of conversation, error was '%s'" % ex)
            return ''

    def print_request(self):

        request = self.c.request
        response = self.c.response

        self.print_request_line()
        self.print_message_header(request)
        self.print_message_steps(request)

        # pretty print raw post data
        if request.postdata_list:
            ansi.echo("underline POST payload (pretty):")
            ansi.echo()
            print '\n'.join(request.postdata_list)

            # pretty print decoded post data
            if request.postdata_decoded:
                ansi.echo("underline POST payload (decoded):")
                ansi.echo()
                pprint.pprint(request.postdata_decoded)

        else:
            print request.body

        self.print_errors(request)

    def print_response(self):

        request = self.c.request
        response = self.c.response

        if int(response.status) < 400:
            ansi.echo("green")
        else:
            ansi.echo("red")
        print self.c.response_line

        self.print_message_header(response)
        self.print_message_steps(response)

        # TODO: better dispatching by response content type
        if response.json_decoded:
            ansi.echo("underline JSON (pretty):")
            ansi.echo()
            if response.json_decoded:
                #from pprint import pprint
                #pprint(decoded)
                import json
                #pretty = json.dumps(decoded, sort_keys=False)
                #pretty = json.dumps(response.json_decoded, sort_keys=True, indent=4)
                pretty = json.dumps(response.json_decoded, sort_keys=False, indent=4)  # TODO: make "sort_keys" configurable
                print pretty
                #ansi.echo("@50;40")
        else:
            #print dir(response)
            f = HttpHeaderFilterStep(self.c, config.http.view.display.body.header.reject)
            if f.apply():
                ansi.echo('yellow <hidden data>')
                ansi.echo('none')
            else:
                print response.body

        self.print_errors(response)


    def print_errors(self, message):

        if message.errors:
            ansi.echo("red")
            for error in message.errors:
                print error
            ansi.echo()


class HttpUrlDumper(HttpDetailDumper):
    """
    dumps details of http messages to console
    uses ansi control codes for shiny colors ;]
    as with almost all ui stuff, this is a mess
    """

    def __init__(self, conversation):
        self.c = conversation

    def dump(self):
        #print dir('')
        print self.c.request_line.ljust(50), '\t', self.format_response_status(with_ansi = True), '\t', self.format_duration(with_ansi = True)
