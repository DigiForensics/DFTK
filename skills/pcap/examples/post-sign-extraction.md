# Example — extract a `sign` from the Nth POST (method only)

A worked *method* for "filter all POSTs, follow the Nth one's stream, give the
`sign`". Use placeholders; do not embed real answers.

## Steps

1. **Filter all POSTs** (report this exact string for the filter question):
   ```
   tshark -r capture.pcap -Y 'http.request.method == "POST"'
   ```
2. **Enumerate with frame numbers** to pick the Nth:
   ```
   tshark -r capture.pcap -Y 'http.request.method == "POST"' \
          -T fields -e frame.number -e http.host -e http.request.uri
   ```
   Note `<FRAME_N>` = the frame of the Nth POST.
3. **Follow its stream** (screenshot target):
   ```
   tshark -r capture.pcap -q -z "follow,http,ascii,<FRAME_N>"
   ```
4. **Read the `sign` directly** (most reliable):
   ```
   tshark -r capture.pcap -Y 'frame.number == <FRAME_N>' \
          -T fields -e urlencoded-form.key -e urlencoded-form.value
   ```
   The `sign` is the value paired with the `sign` key. Report it VERIFIED.

## Claim cards

- claim: filter command for all POST = ?
  evidence: `http.request.method == "POST"`  verification: VERIFIED (canonical)
- claim: Nth POST frame = ?  evidence: enumerated frame list  VERIFIED
- claim: sign value = ?  evidence: `urlencoded-form.value` for `sign` @ frame `<FRAME_N>`  VERIFIED

## Notes

- Pass the **frame number** to `follow,http`, not the tcp.stream index.
- If the body is JSON/multipart, dump `http.file_data` and parse manually.
- If `sign` is encrypted, mark UNRESOLVED and say which field it occupies.
