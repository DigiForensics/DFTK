# Changelog

## 2026-08-14 — initial method-only release
- Static reverse-exe skill distilled from a real suspicious-executable case
  (double-extension `.doc.exe` loader that injects a module into a process,
  decrypts it with AES, then screenshots a target window and re-encrypts the
  capture).
- `SKILL.md`: entry, hard rules, reasoning contract, verification levels,
  relationship to `dftk` / `server-forensics`.
- `references/` (8): static-recon, injection-identification,
  memory-encrypted-payload, crypto-identification, key-extraction,
  process-targeting-screenshot, screenshot-encryption-key,
  obfuscation-and-sandbox.
- `examples/` (2): injection-aes-screenshot, encrypted-bytes-recovery — both
  method-only with `<…>` placeholders (no exam answers).
- `templates/`: claim-card, case-report (reuse verification levels).
- Hard rule enforced: **no exam questions or answers** in the skill; questions
  and correct answers travel with the examination material.
