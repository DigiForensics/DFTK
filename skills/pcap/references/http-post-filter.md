# Filtering HTTP requests in a capture

Wireshark's `http` dissector works on reconstructed HTTP/1.x. Use `tshark`
(headless) for reproducible, scriptable filtering.

## List all POST requests (Q "过滤所有 http post")

```
tshark -r capture.pcap -Y 'http.request.method == "POST"'
```
This is the canonical filter string to report for the "give the filter command"
question. It matches every request whose method is POST.

## Enumerate them with context

Add frame number, host, and URI so you can identify "the Nth" one:
```
tshark -r capture.pcap -Y 'http.request.method == "POST"' \
       -T fields -e frame.number -e http.request.method \
       -e http.host -e http.request.uri
```
- The **frame number** is the stable handle for "the 3rd POST" etc.
- `http.request.uri` shows the query string (`?c=dl&k=…`) but **not** the body.

## All HTTP requests (any method)

```
tshark -r capture.pcap -Y 'http.request' \
       -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
```
Use this to confirm you have not missed a method, and to sanity-check ordering.

## Gotchas

- HTTP/2 (`h2`) over TLS is **not** dissected by the `http` filter — you need a
  keylog file (`tls.keylog_file`) or the captured cleartext. If POSTs are
  missing, check the protocol column; the questions assume cleartext HTTP/1.x.
- A captured request whose body is chunked/gzipped still appears under
  `http.request.method`; the *body* fields need reassembly (next reference).
- Counts: `tshark -r capture.pcap -Y 'http.request.method == "POST"' | wc -l`
  gives the total POST count for "how many POSTs".
