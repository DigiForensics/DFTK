# Claim card

One card per finding. Keep it short and verifiable.

```
## Claim: <one sentence: what the sample does / what artifact it has>

- Verification level: VERIFIED | SUPPORTED | CANDIDATE | UNRESOLVED | UNSUPPORTED
- Evidence:
  - <file/offset or API or string, e.g. `0x4d6000` AES EVP assertion>
  - <disassembled snippet or sandbox observation>
- Method: <which references/ step produced this>
- Capability used: <tool, e.g. pefile / capstone / IDA / sandbox API trace>
- Confidence note: <why this level; what would raise/lower it>
```

Levels (reuse dftk / server-forensics):
- VERIFIED — observed directly in a controlled run or clear static proof.
- SUPPORTED — strong static evidence, behavior not directly observed.
- CANDIDATE — plausible, needs dynamic confirmation.
- UNRESOLVED — could not determine with available tooling.
- UNSUPPORTED — contradicted by evidence.

Do not paste exam answer values into this card for a shared skill; keep them in
your private case notes.
