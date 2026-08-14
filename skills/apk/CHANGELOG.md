# Changelog

## 2026-08-14 — initial method-only release

- Static APK analysis skill distilled from a real suspected-malware APK case
  (proxy `Application` that unpacks `.ccb` secondary dex via a native `decrypt`
  in a custom `.so`; talks to a backend over HTTP POST with a `sign` param).
- `SKILL.md`: entry, hard rules (no install/execute), reasoning contract,
  verification levels, de-examification note, sibling-skill relationships.
- `references/`: manifest-entrypoints (launcher activity + background-running
  capability), native-libraries (loadLibrary name + JNI surface),
  encrypted-secondary-dex (.ccb packing detection + escalation),
  string-and-key-recovery (plaintext key + OpenSSL `DES_*`/`EVP_*` algorithm
  recognition), tooling (jadx/apktool/androguard/unzip/strings).
- `examples/`: entry-and-permissions, native-key-recovery (both method-only,
  placeholders, no answers).
- `templates/`: claim-card, case-report (reuse shared verification levels).
- `README.md`, `CHANGELOG.md`, `LICENSE` (Apache-2.0).

Note: this skill carries no exam questions and no answer values, by design.
