# Following a stream & extracting parameters

Once you have the frame number of the target POST, isolate its conversation and
read the parameter.

## Follow the request's stream

```
tshark -r capture.pcap -q -z "follow,http,ascii,<FRAME>"
```
Shows the full request + response as text. Replace `<FRAME>` with the frame
number of the POST (not the stream index). This is what to screenshot for the
"give the HTTP stream" question.

## Extract URL-encoded form fields directly

If the POST body is `application/x-www-form-urlencoded`, tshark decodes it into
key/value columns:
```
tshark -r capture.pcap -Y 'frame.number == <FRAME>' \
       -T fields -e urlencoded-form.key -e urlencoded-form.value
```
This prints e.g. `timestamp,token,sign<TAB>1749…,,<SIGN_VALUE>` — the `sign`
value is the last comma-separated field. This is the most reliable way to read a
`sign`/`token`/`key` without manual copy from the stream dump.

## Reading a `sign` (or any param)

- If the param is in the **URI** query string, use `http.request.uri` and parse
  `?sign=…&…`.
- If in the **body**, use `urlencoded-form.key`/`urlencoded-form.value` (or
  `follow,http` and read the body line).
- Report the **exact** value tshark printed. That is VERIFIED.

## Gotchas

- `follow,http` takes a **frame number**, not a `tcp.stream` index. Passing the
  stream index silently returns an empty/ wrong conversation.
- Multipart or JSON bodies are not split into `urlencoded-form.*`; for those,
  dump the raw body with `-e http.file_data` and parse manually.
- If the value is encrypted (e.g. a nonce+signature you cannot recompute), mark
  it UNRESOLVED and note what field it sits in — do not fabricate.
