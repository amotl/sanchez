TODO
====

::

  (x) raw http pcap sniffer with tcp flow reassembling
  (x) json decoding
  (o) fine packaging
  (o) basic http filtering
      (o) request by method: GET, POST, DELETE (multiple)
      (o) request by URI (regexp)
      (o) response by header: content-type, etc.
      (o) request/response by special header: e.g. X-Foo-Bar
  (o) conversation aggregator to correlate http requests with its responses
  (o) output control
      +-html
      +-htmlshort
      +-json
  (o) session tracking/aggregation
      (o) by cookie
      (o) by header
  (o) mode control
  (o) ui (using twisted.conch)
  (o) anomaly detection
      +-content-length
      +-invalid-headers
  (o) delaying proxy
