# Tooling for capture analysis

All read-only; nothing replays or transmits.

## tshark (primary)

Headless Wireshark. Key patterns:

- Open / list: `tshark -r capture.pcap`
- Count protocol: `tshark -r capture.pcap -q -z io,phs`
- Filter + fields: `tshark -r capture.pcap -Y '<display filter>' -T fields -e <field>`
- Follow: `tshark -r capture.pcap -q -z "follow,http,ascii,<FRAME>"`
- Form decode: `-e urlencoded-form.key -e urlencoded-form.value`

Display-filter fields of interest: `http.request.method`, `http.request.uri`,
`http.host`, `http.response.code`, `urlencoded-form.key`,
`urlencoded-form.value`, `http.file_data`, `frame.number`, `tcp.stream`.

## scapy (Python, scripting)

For bulk/scripted extraction when tshark fields are awkward:
```python
from scapy.all import rdpcap, TCP
pkts = rdpcap("capture.pcap")
for p in pkts:
    if TCP in p and p[TCP].payload:
        data = bytes(p[TCP].payload)
        if b"POST" in data.split(b"\r\n")[0]:
            ...  # parse request line / body
```
Use scapy when you need custom reassembly or to iterate many captures.

## Evidence hygiene

- Hash the capture (`sha256sum capture.pcap`) and record it.
- Keep the original immutable; analyze a copy.
- Record the `tshark` / Wireshark version — dissector behavior drifts between
  releases (field names especially).
- For the "screenshot" question, capture the exact `tshark` command *and* its
  output; that is the reproducible evidence.
