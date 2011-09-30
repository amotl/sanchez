import dpkt
import types

def pack_hdr(self):
    return ''.join([ '%s: %s\r\n' % t for t in self.headers.iteritems() ])

def pack_hdr_pretty(self):
    headers_list = []
    for name, value in self.headers.iteritems():
        # for multiple headers with same name, handle lists as well
        if not type(value) is types.ListType:
            value = [value]
        for item in value:
            entry = '%s: %s' % (name.title(), item)
            headers_list.append(entry)
    headers_list.sort()
    headers_string = '\r\n'.join(headers_list) + '\r\n'
    return headers_string

def patch_dpkt():
    dpkt.http.Message.pack_hdr_pretty = pack_hdr_pretty
