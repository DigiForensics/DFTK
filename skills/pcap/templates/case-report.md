# Case report — PCAP / traffic capture analysis

Consolidated output for one capture. Keep findings ordered by the original
question numbering, but do **not** embed answer values here if this report will
be shared as a skill — keep answers in private case notes and present only the
method/structure.

```
# PCAP analysis report — <capture name / sha256>

## 1. Evidence
- Source: <evidence path / how obtained>
- SHA-256: <capture hash>
- Tools: tshark <ver>

## 2. Request filtering
- Filter command: http.request.method == "POST"
- Total POST count: <N>
- Enumerated: <frame, host, uri> ...

## 3. Target stream / parameter
- Nth POST frame: <FRAME_N>
- Stream follow: tshark -q -z follow,http,ascii,<FRAME_N>
- Param <sign/token/key>: <VALUE>  [VERIFIED]
  evidence: urlencoded-form.value @ frame <FRAME_N>

## 4. Escalation (if any)
- <encrypted param / HTTP2-TLS needs keylog>

## 5. Verification summary
| claim | level | evidence |
|-------|-------|----------|
| ...   | ...   | ...      |
```
