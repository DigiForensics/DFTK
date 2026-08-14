# Changelog

## 2026-08-14 — initial method-only release

- Static PCAP analysis skill distilled from a real case (app HTTP-POST traffic
  with a client-computed `sign` parameter).
- `SKILL.md`: entry, hard rules (no replay/re-inject), reasoning contract,
  verification levels, de-examification note, sibling-skill relationships.
- `references/`: http-post-filter (`http.request.method == "POST"` + enumeration
  by frame), follow-stream-params (`follow,http,ascii,<FRAME>` + form-field
  decode), tooling (tshark / scapy).
- `examples/`: post-sign-extraction (method-only, placeholders, no answers).
- `templates/`: claim-card, case-report (reuse shared verification levels).
- `README.md`, `CHANGELOG.md`, `LICENSE` (Apache-2.0).

Note: this skill carries no exam questions and no answer values, by design.
