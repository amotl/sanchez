# -*- coding: utf-8 -*-

from sanchez.utils import ansi


class HttpConversation(object):

    def __init__(self, addr, request, response):
        self.addr = addr

        self.request = request
        if not hasattr(self.request, 'postdata'):
            self.request.postdata = []

        self.response = response
        if not hasattr(self.response, 'errors'):
            self.response.errors = []
        if not hasattr(self.response, 'json_decoded'):
            self.response.json_decoded = None


class HttpFilter(object):
    '''
    filters http messages
    '''

    def __init__(self, conversation):
        self.c = conversation

    def accept(self):
        return \
            'json' in self.c.request.headers.get('accept', '').lower() \
            or \
            'json' in self.c.response.headers.get('content-type', '').lower()


class HttpResponseDecoder(object):

    def __init__(self, conversation):
        self.c = conversation

    def decode(self):
        self.decode_gzip()
        self.decode_json()

    def decode_gzip(self):
        request = self.c.request
        response = self.c.response

        if 'gzip' in response.headers.get('content-encoding', ''):

            import StringIO
            import gzip

            try:
                gzipper = gzip.GzipFile(fileobj = StringIO.StringIO(response.body))
                response.body = gzipper.read()
                return True

            except Exception, e:
                response.errors.append("Could not uncompress gzip (length=%d): %s" % (len(response.body), e))
                return False


    def decode_json(self):
        request = self.c.request
        response = self.c.response

        if 'json' in response.headers.get('content-type', '').lower():
            try:
                import json
                decoded = json.loads(response.body)
                response.json_decoded = decoded
                return True

            except Exception, e:
                response.errors.append("Could not parse json: %s\nRaw body was:\n%s" % (e, response.body))
                return False


class HttpRequestDecoder(object):

    def __init__(self, conversation):
        self.c = conversation

    def decode(self):
        self.decode_post()

    def decode_post(self):

        request = self.c.request

        # pretty print post data
        if request.method == 'POST':
            body = request.body
            post_parts = body.split('&')
            postdata = []
            for part in post_parts:
                key, value = part.split('=', 1)
                entry = "%s: %s" % (key, value)
                postdata.append(entry)
            request.postdata = postdata
            return True


class HttpDumper(object):
    '''
    dumps http messages to console
    '''

    def __init__(self, conversation):
        self.c = conversation

    def print_header(self, request = False, response = False):
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

        print
        ansi.echo("blue bold underline")
        print conversation_header
        ansi.echo()


    def print_request(self):

        request = self.c.request
        response = self.c.response

        print '%s %s %s/%s' % (request.method, request.uri, 'HTTP', request.version), "\t",
        if int(response.status) < 400:
            ansi.echo("green [%s %s]" % (response.status, response.reason))
        else:
            ansi.echo("red   [%s %s]" % (response.status, response.reason))
        ansi.echo()
        print request.pack_hdr()

        # pretty print post data
        if request.postdata:
            ansi.echo("underline POST payload (pretty):")
            ansi.echo()
            print '\n'.join(request.postdata)


    def print_response(self):

        request = self.c.request
        response = self.c.response

        if int(response.status) < 400:
            ansi.echo("green")
        else:
            ansi.echo("red")
        print '%s/%s %s %s' % ('HTTP', response.version, response.status, response.reason)
        ansi.echo()
        print response.pack_hdr()

        if response.json_decoded:
            ansi.echo("underline JSON (pretty):")
            ansi.echo()
            if response.json_decoded:
                #from pprint import pprint
                #pprint(decoded)
                import json
                pretty = json.dumps(response.json_decoded, sort_keys=True, indent=4)
                #pretty = json.dumps(decoded, sort_keys=False)
                print pretty
                #ansi.echo("@50;40")

        if response.errors:
            ansi.echo("red")
            for error in response.errors:
                print error
            ansi.echo()
