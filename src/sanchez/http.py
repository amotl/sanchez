# -*- coding: utf-8 -*-

import sys
import urllib
import urlparse
import pprint

from sanchez import config
from sanchez.utils import ansi


class HttpArtifact(object):
    """
    just a container object for bundling the
    magic triple as of (addr, kind [request, response], data)
    """

    def __init__(self, addr, kind, data):
        self.addr = addr
        self.kind = kind
        self.data = data

    def __str__(self):
        data = [
            '-' * 42,
            str(self.addr) + ' ' + self.kind,
            self.data,
        ]
        return '\n'.join(data)


class HttpConversation(object):
    """
    just a container object for bundling the
    magic triple as of (addr, request, response)
    """

    def __init__(self, addr, request, response):
        self.addr = addr
        self.request = request
        self.response = response
        self.initialize()

    def initialize(self):

        # request
        if self.request:
            if not hasattr(self.request, 'postdata_dict'):
                self.request.postdata_dict = {}
            if not hasattr(self.request, 'postdata_list'):
                self.request.postdata_list = []
            if not hasattr(self.request, 'postdata_decoded'):
                self.request.postdata_decoded = {}

        # response
        if self.response:
            if not hasattr(self.response, 'errors'):
                self.response.errors = []
            if not hasattr(self.response, 'json_decoded'):
                self.response.json_decoded = None


class HttpDecoderChain(object):
    """
    main sequence to run through all filtering and decoding steps
    """

    def __init__(self, conversation):
        self.conversation = conversation

    def process(self):

        # apply e.g. http header filter
        filter_header = HttpHeaderFilter(self.conversation)
        if not filter_header.accept():
            return False

        filter_method = HttpMethodFilter(self.conversation)
        if not filter_method.accept():
            return False

        # request: decode post data, etc.
        decoder_request = HttpRequestDecoder(self.conversation)
        decoder_request.decode()

        # response: decode gzip, json, etc.
        decoder_response = HttpResponseDecoder(self.conversation)
        decoder_response.decode()

        return True


class HttpHeaderFilter(object):
    """
    filters http messages by conditions applied to http headers
    """

    def __init__(self, conversation):
        self.c = conversation

    def accept(self):

        # v1 - to shed more light onto this
        """
        return \
            'json' in self.c.request.headers.get('accept', '').lower() \
            or \
            'json' in self.c.response.headers.get('content-type', '').lower()
        """

        # v2 - generic logic controlled by sanchez.config (~/.sanchez/config.py)
        if not config.http.filter.accept.header:
            return True

        for msg in self.c.request, self.c.response:
            for header, value in config.http.filter.accept.header.iteritems():
                if value in msg.headers.get(header, '').lower():
                    return True

        return False


class HttpMethodFilter(object):
    """
    filters http messages by conditions applied to the http request method
    """

    def __init__(self, conversation):
        self.c = conversation

    def accept(self):

        # generic logic controlled by sanchez.config (~/.sanchez/config.py)
        if not config.http.filter.accept.method:
            return True

        for method in config.http.filter.accept.method:
            if method == self.c.request.method.upper():
                return True

        return False

class HttpResponseDecoder(object):
    """
    decodes body of http response
    order: gzip, json, custom plugin decoders
    """

    plugins = []


    def __init__(self, conversation):
        self.c = conversation


    @classmethod
    def plugin_register(cls, plugin):
        """
        very simple plugin mechanism
        """
        HttpResponseDecoder.plugins.append(plugin)


    def decode(self):
        """
        main sequence to run through all response.body decoding steps
        """

        if not self.c.response: return

        # builtin steps
        self.decode_gzip()
        self.decode_json()

        # plugin steps
        for plugin in self.plugins:
            p = plugin(self.c)
            p.decode()


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
    """
    decodes body of http request
    order: postdata, custom plugin decoders
    """

    def __init__(self, conversation):
        self.c = conversation

    def decode(self):

        request = self.c.request
        if not request: return

        # pretty print post data
        if request.headers.get('content-type', '').lower().startswith('application/x-www-form-urlencoded'):
            post_parts = request.body.split('&')
            postdata_list = []
            for part in post_parts:
                key, value = part.split('=', 1)
                entry = "%s: %s" % (key, urllib.unquote_plus(value))
                postdata_list.append(entry)

            request.postdata_dict = urlparse.parse_qs(request.body)
            request.postdata_list = postdata_list

            return True


class HttpDumper(object):
    """
    dumps details of http messages to console
    uses ansi control codes for shiny colors ;]
    as with almost all ui stuff, this is a mess
    """

    def __init__(self, conversation):
        self.c = conversation

    def dump(self):

        if self.c.request:
            self.print_header(request = True)
            self.print_request()

        if self.c.response:
            self.print_header(response = True)
            self.print_response()


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

        # print status of correlated response on top, if available
        # TODO: refactor to separate method "print_conversation_header"
        if response:
            if int(response.status) < 400:
                status_color = 'green'
            else:
                status_color = 'red'
            ansi.echo("%s [%s %s]" % (status_color, response.status, response.reason))
        else:
            print

        ansi.echo()
        print request.pack_hdr()

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
            print response.body

        if response.errors:
            ansi.echo("red")
            for error in response.errors:
                print error
            ansi.echo()
