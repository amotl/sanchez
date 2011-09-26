# -*- coding: utf-8 -*-

import sys
import re
import urllib
import urlparse
import pprint
import types

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

    instances = 0

    def __init__(self, addr, request, response):
        HttpConversation.instances += 1
        self.seqno = HttpConversation.instances

        self.addr = addr
        self._request = None
        self._response = None
        self.request = request
        self.response = response

    @property
    def request(self):
        return self._request

    @request.setter
    def request(self, obj):
        if not obj: return
        obj.steps = []
        if not hasattr(obj, 'postdata_dict'):
            obj.postdata_dict = {}
        if not hasattr(obj, 'postdata_list'):
            obj.postdata_list = []
        if not hasattr(obj, 'postdata_decoded'):
            obj.postdata_decoded = {}
        self._request = obj

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, obj):
        if not obj: return
        obj.steps = []
        if not hasattr(obj, 'errors'):
            obj.errors = []
        if not hasattr(obj, 'correlated'):
            obj.correlated = False
        if not hasattr(obj, 'json_decoded'):
            obj.json_decoded = None
        self._response = obj

    @property
    def request_line(self):
        request = self.request
        return '%s %s %s/%s' % (request.method, request.uri, 'HTTP', request.version)

    @property
    def response_line(self):
        response = self.response
        return '%s/%s %s %s' % ('HTTP', response.version, response.status, response.reason)


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

        filter_method = HttpTotalFilter(self.conversation)
        if not filter_method.accept():
            return False

        # request: decode post data, etc.
        decoder_request = HttpRequestDecoder(self.conversation)
        decoder_request.decode()

        # response: decode gzip, json, etc.
        decoder_response = HttpResponseDecoder(self.conversation)
        decoder_response.decode()

        return True


class HttpHeaderFilterStep(object):
    """
    filters http messages by conditions applied to http headers
    generic logic controlled by sanchez.config (~/.sanchez/config.py)
    """

    def __init__(self, conversation, configuration):
        self.c = conversation
        self.config = configuration

    def match(self, message, header, value):
        if value in message.headers.get(header, '').lower():
            return True

    def matchmulti(self, config, message):
        for header, value in config.iteritems():
            if self.match(message, header, value):
                return True

    def apply(self):

        if not self.config:
            return True

        for msg in self.c.request, self.c.response:
            if msg is None: continue
            if type(self.config) is types.ListType:
                for item in self.config:
                    if self.matchmulti(item, msg):
                        return True

            elif type(self.config) is types.DictType:
                if self.matchmulti(self.config, msg):
                    return True

        return False


class HttpTotalFilter(object):
    """
    filters http messages by conditions applied to http headers
    """

    def __init__(self, conversation):
        self.c = conversation

    def accept(self):

        # v2 - generic logic controlled by sanchez.config (~/.sanchez/config.py)
        if not config.http.filter.total:
            return True

        payload = \
            self.c.request_line + self.c.request.pack_hdr() + self.c.request.pack_hdr_pretty() + self.c.request.body + \
            self.c.response_line + self.c.response.pack_hdr() + self.c.response.pack_hdr_pretty() + self.c.response.body
        #print payload

        if config.http.filter.total.text:
            if config.http.filter.total.text in payload:
                return True
        elif config.http.filter.total.regex:
            if re.search(config.http.filter.total.regex, payload, re.DOTALL):
                return True

        return False

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
            if not msg: continue
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
            # TODO: honor X-Http-Method-Override
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
        self.decode_charset()
        self.decode_json()

        # plugin steps
        for plugin in self.plugins:
            p = plugin(self.c)
            p.decode()


    def decode_gzip(self):

        if not config.http.decode.body.gzip: return

        request = self.c.request
        response = self.c.response

        if 'gzip' in response.headers.get('content-encoding', ''):

            import StringIO
            import gzip

            try:
                gzipper = gzip.GzipFile(fileobj = StringIO.StringIO(response.body))
                response.body = gzipper.read()
                response.steps.append('gzip-decoded')
                return True

            except Exception, e:
                response.errors.append("Could not uncompress gzip (length=%d): %s" % (len(response.body), e))
                return False

    def decode_charset(self):

        if not config.http.decode.body.charset: return

        response = self.c.response

        # Content-Type: text/html; charset=iso-8859-1

        try:
            content_type_raw = response.headers.get('content-type', '').lower()
            parts = content_type_raw.split(';')
            if len(parts) > 1:
                parts = [part.strip() for part in parts]
                attributes = {}
                for attrib_raw in parts[1:]:
                    name, value = attrib_raw.split('=')
                    attributes[name.strip()] = value.strip()
                if attributes.has_key('charset'):
                    charset = attributes['charset']
                    try:
                        response.body = response.body.decode(charset)
                    except Exception, e:
                        response.errors.append("Could not decode body from charset '%s': %s" % (charset, e))
                        return False
                    response.steps.append('charset-decoded')
                    return True

        except Exception, e:
            response.errors.append("Could not decode body (charset): %s" % (e))
            #raise
            return False

    def decode_json(self):

        if not config.http.decode.body.json: return

        request = self.c.request
        response = self.c.response

        if 'json' in response.headers.get('content-type', '').lower():
            try:
                import json
                body = response.body
                if config.http.decode.body.json_obfuscation and body.startswith(config.http.decode.body.json_obfuscation):
                    response.steps.append('json-unobfuscated')
                    body = body.replace(config.http.decode.body.json_obfuscation, '')
                decoded = json.loads(body)
                response.json_decoded = decoded
                response.steps.append('json-decoded')
                return True

            except Exception, e:
                response.errors.append("Could not parse json: %s" % (e))
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

        response = self.c.response

        print self.c.request_line, "\t",

        # print status of correlated response on top, if available
        # TODO: refactor to separate method "print_conversation_header"
        if response is not None:
            if int(response.status) < 400:
                status_color = 'green'
            else:
                status_color = 'red'
            ansi.echo("%s [%s %s]" % (status_color, response.status, response.reason))
            ansi.echo("none")
        else:
            print

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

        if response.errors:
            ansi.echo("red")
            for error in response.errors:
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
        self.print_request_line()
