---
name: pcap
description: >-
  Method-only playbook for static network-capture (PCAP/PCAPNG) analysis:
  filtering HTTP requests (e.g. all POST methods), following a request's stream,
  and extracting URL-encoded parameters (sign/token/key) from request bodies.
  Read-only posture — never replay or re-inject the traffic. Teaches technique,
  not answers.
license: Apache-2.0
copyright: Copyright 2026 DyNooob @ DigiForensics
---

# PCAP / traffic capture (static, read-only)

Progressive-disclosure skill for analyzing a packet capture (`.pcap` /
`.pcapng`) **without replaying or re-injecting it**. It covers the techniques
behind recurring finding classes:

1. **Request filtering** — show all HTTP POST (or GET) requests in a capture.
2. **Stream following** — isolate one request/response conversation.
3. **Parameter extraction** — pull `sign` / `token` / `key` values from a
   request's URL or `application/x-www-form-urlencoded` body.

This skill is **method-only**. It contains no exam questions and no answer
values. Questions and their correct answers travel with the examination
material, not the shared skill.

## Hard rules

- **Never replay, re-inject, or transmit** packets from the capture. Read-only
  dissection only.
- Preserve the original capture immutable. Copy it to a working directory.
- Distinguish **fact** (a literal field value tshark printed) from **inference**.
  When a parameter is encrypted/missing, mark it UNRESOLVED.

## Reasoning contract

claim → evidence → capability → execution → verification

- **claim**: the specific question asked (e.g. "what is the `sign` of the 3rd
  POST?").
- **evidence**: the exact filter and the field/stream that yielded the value.
- **capability**: `tshark` (Wireshark CLI) or `scapy`.
- **execution**: the command run (reproducible).
- **verification**: VERIFIED / SUPPORTED / CANDIDATE / UNRESOLVED / UNSUPPORTED.

## Verification levels

- **VERIFIED** — tshark printed the literal value from the capture.
- **SUPPORTED** — value implied by multiple fields (e.g. POST body form keys
  list includes `sign`).
- **CANDIDATE** — one field points to it, needs corroboration.
- **UNRESOLVED** — parameter absent/encrypted in the capture.
- **UNSUPPORTED** — contradicted by evidence.

## Typical workflow

1. Copy the capture; open it with `tshark -r file.pcap`.
2. Filter the requests you care about:
   `tshark -r file.pcap -Y 'http.request.method == "POST"'`.
3. Enumerate them with frame numbers + URI to pick "the Nth" one.
4. Follow that request's stream / extract its form fields to read the parameter.
5. Report the literal value; for the screenshot question, note the exact filter
   string used.

## Relationship to sibling skills

- `dftk` — local file/archive/image forensics (no live traffic). Use its
  read-only tools for the PCAP *file* itself (hash, type).
- `apk` / `reverse-exe` — the endpoint that generated the traffic; correlate
  here, analyze the binary there.
- `server-forensics` — live server triage (uses 0 dftk tools).
- This skill uses 0 `dftk` tools and is not bundled in the `dftk` wheel.

## De-examification note

Distilled from a real case where an app's HTTP POST traffic carried a `sign`
parameter computed client-side. All question numbers and answer values were
stripped; only method remains. Keep exams' questions/answers with the
examination material.
