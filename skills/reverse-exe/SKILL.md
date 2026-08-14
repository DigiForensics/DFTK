---
name: reverse-exe
description: >-
  Method-only playbook for static reverse engineering of a suspicious
  executable: process-injection identification, in-memory encrypted-payload
  recovery, crypto-algorithm and key extraction, and process-targeting +
  screenshot-capture forensics. Read-only posture — never execute the sample on
  the analysis host. Teaches technique, not answers.
license: Apache-2.0
copyright: Copyright 2026 DyNooob @ DigiForensics
---

# Reverse / EXE (static, read-only)

Progressive-disclosure skill for analyzing a suspicious executable sample (typically
a Windows EXE/DLL) **without running it**. It covers the techniques behind
recurring findings classes:

1. **Remote-thread injection** — which process the sample injects into.
2. **Encrypted payload in memory** — which algorithm decrypts it, and the key.
3. **Process-targeting + screenshot capture** — which process/window it hunts,
   how it captures the screen, and the key used to re-encrypt the capture.

This skill is **method-only**. It contains no exam questions and no answer
values. Questions and their correct answers travel with the examination
material; only the analytic technique is distilled here.

## When to use

- A forensic task hands you a suspicious executable and asks *what it does*,
  *where it injects*, *how its payload is encrypted*, or *what it screenshots*.
- You need to recover a hidden string/key/module from a binary via static
  analysis (IDA / Ghidra / strings / pefile / capstone) and/or a throwaway
  sandbox.
- You must produce a claim→evidence write-up that an examiner can verify.

## When NOT to use

- You have a live server to triage → use `server-forensics`.
- You have local disk/image/archive artifacts → use `dftk` (68 read-only tools).
- You are asked to *detonate* the sample for behavior → only inside an isolated
  VM/sandbox; see `references/obfuscation-and-sandbox.md`. Never on the host.

## Hard rules

1. **Never execute the sample on the analysis host.** Static-first. Dynamic only
   in an isolated snapshot-able VM.
2. **No exam content in this skill.** No question numbers, no answer strings,
   no target-process names from a specific exam. Technique only.
3. **Verify, don't assert.** Every claim gets a verification level (below).
4. **Keep the evidence immutable.** Work on a copy; record hashes of the
   original before anything else.

## Reasoning contract (reuse from dftk / server-forensics)

claim → evidence → capability → execution → verification

- **claim**: hypothesized behavior/artifact (e.g., "module is AES-256-CBC").
- **evidence**: the bytes/strings/APIs that support it.
- **capability**: the tool that can confirm (disassembler, sandbox trace).
- **execution**: run it (static or sandboxed).
- **verification**: assign a level.

## Verification levels

- **VERIFIED** — observed directly in a controlled run or clear static proof.
- **SUPPORTED** — strong static evidence, behavior not directly observed.
- **CANDIDATE** — plausible but needs dynamic confirmation.
- **UNRESOLVED** — could not determine with available tooling.
- **UNSUPPORTED** — contradicted by evidence.

## Tooling (external; not part of dftk)

- **Triaging**: `pefile` (Python), `Detect It Easy` (packer/compiler), `strings`
  (ASCII + UTF-16LE).
- **Disassembly**: IDA Pro / Ghidra (preferred — resolve imports + xrefs),
  `capstone` (scripted disasm when no GUI).
- **Dynamic (sandbox only)**: API Monitor / Rohitab, Process Monitor, a
  snapshot-able VM. Never on the host.
- **Scripting**: Python + `pefile` + `capstone` + `zipfile` (embedded docs).

## Progressive disclosure — references/

Load only what the task needs:

- `references/static-recon.md` — hashing, section entropy, embedded resources,
  import triage, spotting statically-linked crypto (OpenSSL).
- `references/injection-identification.md` — remote-thread injection chain and
  how to read the target process name.
- `references/memory-encrypted-payload.md` — payload stored as ciphertext in
  memory; locating it; why static key recovery may fail.
- `references/crypto-identification.md` — recognize AES/RC4/DES/TEA/XOR from
  constants and the OpenSSL `EVP` assertion; report algorithm uppercase.
- `references/key-extraction.md` — plaintext keys vs runtime-decoded keys;
  tracing `EVP_CipherInit` / decode routines; why a 1–2 byte XOR brute-force is
  often insufficient.
- `references/process-targeting-screenshot.md` — `FindWindow`/`EnumWindows` +
  process-name lookup, `BitBlt`/`PrintWindow` capture, re-encrypt to disk.
- `references/screenshot-encryption-key.md` — the *second* key (the screenshot
  payload) is usually distinct from the module-decrypt key; watch for a `0x…`
  pointer to a DWORD/buffer.
- `references/obfuscation-and-sandbox.md` — custom IAT/thunk tables and string
  encryption: when static hits a wall, move to a sandbox API-trace or a real
  disassembler; never execute on the host.

## Examples (method only)

- `examples/injection-aes-screenshot.md` — a synthetic walkthrough using
  `<TARGET_PROCESS>` / `<ALGORITHM>` / `<MODULE_KEY>` / `<SHOT_TARGET>` /
  `<SHOT_KEY>` placeholders. No real answers.
- `examples/encrypted-bytes-recovery.md` — method for locating and decrypting an
  in-memory encrypted module.

## Report templates

- `templates/claim-card.md` — one claim→evidence card per finding.
- `templates/case-report.md` — consolidated report; keep findings ordered by
  the original question numbering but do not embed answer values here.

## Relationship to sibling skills

- `dftk` — local file/archive/image forensics (no live binary behavior).
- `server-forensics` — live Windows/Linux server triage (uses 0 dftk tools).
- This skill — static executable reverse engineering. It complements both; it does not
  depend on dftk and is not bundled in the dftk wheel.

## De-examification note

This skill was distilled from a real malicious-program analysis. All exam
question numbers and answer values were stripped; only the method remains. If
you are preparing an examination, keep the questions and correct answers with
the examination material — never paste them into a shared skill.
