# Contributing to DFTK

DFTK favors general, bounded forensic operations with source-linked results.
The host Agent owns investigation strategy; avoid embedding fixed answers,
password guesses, target identities or a compulsory investigation sequence.

## Contribution contract

- Preserve source evidence and write derived material separately.
- Declare parameter types/bounds, host-path roles, safety, network behavior,
  dependencies and produced types before exposing a capability.
- Return structured Observations with locators, raw values and explicit omissions;
  partial/failure states must not become negative findings.
- Preserve useful recovered evidence when another item fails; do not silently
  substitute an unrelated parser or reclassify a heuristic as direct evidence.
- Keep native image disclosure and CPU-OCR consent boundaries intact. Do not add
  examination-time model downloads or automatic password/algorithm search loops.
- Use meaningful regression fixtures and checks for the behavior being changed.

Follow the [development guide](docs/development.md) for a correctly selected Python
environment, the CI coverage gate, static manifest generation and wheel validation.
Run `python scripts/check_docs.py` when editing documentation. Update both language
entry pages and synchronize the companion capability catalog when contracts change.

## Review and release

A change description should state the concrete trigger, resulting behavior,
validation and material limits. Keep secrets/real evidence out of fixtures and PRs.
Avoid runtime dependencies unless they materially improve the supported operation;
optional integrations should remain identifiable and explain their installation gap.

Runtime code/contracts and execution policy live here. Investigation methodology,
specialist references and templates live in
[DFTK-skill](https://github.com/DigiForensics/DFTK-skill).
See [architecture](ARCHITECTURE.md), [safety](SAFETY.md),
[documentation policy](docs/documentation.md) and [release process](PUBLISHING.md).
Security reports follow [SECURITY.md](SECURITY.md).
