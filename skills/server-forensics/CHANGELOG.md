# Changelog

## 1.0.0 (2026-08-14)

- Initial standalone skill: live Linux server and web-application forensics via standard read-only tooling.
- Covers 7 blind spots found during a course server investigation:
  - partition identity (PARTUUID) — `references/partition-identity.md`
  - service/port enumeration and "对外端口" meaning — `references/service-port-enum.md`
  - web-app config & credential review — `references/web-config-review.md`
  - live RDBMS forensics (MySQL/MariaDB PII, aggregation, hash format) — `references/live-db-forensics.md`
  - encrypted-archive identification & decryption (OpenSSL `Salted__`, `aes-256-cbc`) — `references/encrypted-archive.md`
  - containerized evidence access (`docker inspect/exec`, volume MySQL, bridge-auth gotcha) — `references/container-evidence.md`
  - SSH live-forensics workflow — `references/ssh-live.md`
- `references/overview.md` (scope, reasoning loop, decision aid) and `references/recon.md` (triage).
- `examples/server-investigation.md`: generic multi-question walkthrough (method only — exam questions/answers kept out of the skill).
- `examples/encrypted-archive-decrypt.md`: OpenSSL archive decryption method (no exam question embedded).
- `templates/`: claim-card, finding, case-report (reuse DFTK verification levels).
- Complements the `dftk` skill: prefer DFTK for local files/images; this skill for running servers.
