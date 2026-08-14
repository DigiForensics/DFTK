# reverse-exe (skill)

Method-only playbook for **static** reverse engineering of a suspicious
executable: process-injection identification, in-memory encrypted
payload recovery, crypto-algorithm and key extraction, and process-targeting +
screenshot-capture forensics.

**Read-only posture:** never execute the sample on the analysis host. Static
first; dynamic only in an isolated, snapshot-able VM.

## What it is / isn't
- It is a *technique* skill. It contains **no exam questions and no answer
  values**.
- It complements `dftk` (local artifact forensics) and `server-forensics` (live
  server triage). It uses 0 `dftk` tools and is not bundled in the `dftk` wheel.

## Layout
```
reverse-exe/
  SKILL.md                        # entry + reasoning contract + hard rules
  references/                      # load on demand
    static-recon.md
    injection-identification.md
    memory-encrypted-payload.md
    crypto-identification.md
    key-extraction.md
    process-targeting-screenshot.md
    screenshot-encryption-key.md
    obfuscation-and-sandbox.md
  examples/                        # method-only walkthroughs (no answers)
    injection-aes-screenshot.md
    encrypted-bytes-recovery.md
  templates/                       # claim-card.md, case-report.md
  README.md  CHANGELOG.md  LICENSE
```

## Install (copy the directory)
This skill lives inside the DFTK repository at `skills/reverse-exe/`
(alongside `skills/dftk`). It is **not** published to PyPI and not auto-installed
by `dftk`. To use it as a standalone skill, copy the directory:
```bash
git clone https://github.com/DigiForensics/DFTK
cp -r DFTK/skills/reverse-exe ~/.workbuddy/skills/reverse-exe
```

## Reasoning contract
claim → evidence → capability → execution → verification, with levels
VERIFIED / SUPPORTED / CANDIDATE / UNRESOLVED / UNSUPPORTED (shared with
`dftk` and `server-forensics`).

## De-examification
Distilled from a real malicious-program analysis. All question numbers and
answer values were stripped; only method remains. Keep exams' questions/answers
with the examination material.
