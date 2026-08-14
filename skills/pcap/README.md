# pcap (skill)

Method-only playbook for **static** network-capture (PCAP/PCAPNG) analysis:
filtering HTTP requests (all POST methods), following a request's stream, and
extracting URL-encoded parameters (`sign` / `token` / `key`) from request
bodies.

**Read-only posture:** never replay or re-inject the traffic. Dissect only.

## What it is / isn't

- It is a *technique* skill. It contains **no exam questions and no answer
  values**.
- It complements `dftk` (local file forensics — hash/type the capture file),
  `apk` / `reverse-exe` (the endpoint that generated the traffic), and
  `server-forensics` (live server). It uses 0 `dftk` tools and is not bundled in
  the `dftk` wheel.

## Layout

```
pcap/
  SKILL.md                        # entry + reasoning contract + hard rules
  references/                      # load on demand
    http-post-filter.md
    follow-stream-params.md
    tooling.md
  examples/                        # method-only walkthroughs (no answers)
    post-sign-extraction.md
  templates/                       # claim-card.md, case-report.md
  README.md  CHANGELOG.md  LICENSE
```

## Install (copy the directory)

This skill lives inside the DFTK repository at `skills/pcap/` (alongside
`skills/dftk`). It is **not** published to PyPI and not auto-installed by
`dftk`. To use it as a standalone skill, copy the directory:

```bash
git clone https://github.com/DigiForensics/DFTK
cp -r DFTK/skills/pcap ~/.workbuddy/skills/pcap
```

## Reasoning contract

claim → evidence → capability → execution → verification, with levels VERIFIED /
SUPPORTED / CANDIDATE / UNRESOLVED / UNSUPPORTED (shared with `dftk`,
`server-forensics`, `reverse-exe`, `apk`).

## De-examification

Distilled from a real case where an app's HTTP POST traffic carried a `sign`
parameter computed client-side. All question numbers and answer values were
stripped; only method remains. Keep exams' questions/answers with the
examination material.
