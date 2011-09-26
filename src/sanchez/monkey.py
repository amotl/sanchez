import dpkt

def pack_hdr(self):
    return ''.join([ '%s: %s\r\n' % t for t in self.headers.iteritems() ])

def pack_hdr_pretty(self):
    headers_list = []
    for name, value in self.headers.iteritems():
        entry = '%s: %s' % (name.title(), value)
        headers_list.append(entry)
    headers_list.sort()
    headers_string = '\r\n'.join(headers_list) + '\r\n'
    return headers_string

def patch_dpkt():
    dpkt.http.Message.pack_hdr_pretty = pack_hdr_pretty
