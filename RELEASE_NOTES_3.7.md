# DFTK 3.7.0

DFTK supplies perception, bounded actions and source-linked memory; the host
Agent chooses the investigation path and evaluates the resulting claims.

This release provides **136 capabilities across 29 domains**, including 121
primitives and 15 recipes: 131 READ_ONLY and five STATEFUL tools. The MCP surface
has eight meta-tools. Install the matching `v3.7.0` DFTK-skill bundle.

## Perception

- `dftk_view_media` returns native MCP image content for a single image/crop,
  numbered still-image contact sheet, or timestamped video samples.
- Visual disclosure requires scoped user permission and confirmed host-model
  image support on each call. Without either, report discovered media without
  pixels. These are host attestations; DFTK cannot authenticate chat approval.
- `media.ocr` and `media.ocr_batch` use local CUDA/MPS by default. CPU execution
  requires affirmative consent after explaining the performance cost. No silent
  CPU fallback, examination-time model downloads or remote OCR uploads.
- OCR returns raw text, confidence, boxes, source hashes and processing scope.
  Batch shares model initialisation, records per-file outcomes and returns
  unattempted inputs at a cooperative time/result budget.

## Evidence access and continuity

- `evidence.browse` and `file.read_text` expose bounded directory/text windows.
- Case `artifacts` / `note_artifact` preserve unread evidence and analyst
  dispositions; declined/deferred media remain known coverage gaps.
- Registered archive/filesystem/HTTP/decryption outputs can be consumed directly
  by evidence-input tools under the same Case, after path and hash checks.
- Worker timeouts/crashes remain in attempts even without a complete Observation.
- Repeated Recipe facts have unique keys; persisted results support JSON Pointer,
  evidence and provenance paging without rerunning a parser.

## Encrypted containers

- ZIP inventory exposes member encryption flags and continuation. Extraction
  accepts one supplied password and retains accessible members when others block.
- `crypto.openssl_decrypt` makes one supplied-candidate attempt with explicit
  AES CBC/CTR, KDF and expected inner-format settings. A `Salted__` header does
  not establish the password or cipher/KDF. Credential-source references are
  supplied by the host and are not independently verified.
- Only structurally validated ZIP/SQLite/GZIP/raw TAR output is registered. ZIP
  checks the central directory rather than member CRC/content. Validation does
  not authenticate acquisition origin. No automatic guessing or retry loop.

## Validation and limits

Regression tests cover consent gates, native image transport, GPU/CPU dispatch,
batch continuation, coordinate mapping, workspace containment, modified-derived
file rejection, password redaction and OCR-to-decryption-to-SQLite composition.
Synthetic real-MPS validation recovered a clue from two images, decrypted once,
queried the nested database and preserved all source hashes. This does not
establish real-case evidence recall or actual CUDA performance.

Video perception samples frames only; audio and unsampled content remain unread.
Some AES ZIP methods and RAR/7z decoding remain unsupported. Model weights and
FFmpeg/FFprobe need separate provisioning. Equivalent repeated calls are not
globally blocked; the host still owns scheduling and recovery budgets.

## Install

```bash
python -m pip install --upgrade "dftk[mcp,ocr]"
dftk skill --install
```

See [media perception](docs/media-perception.md) for weights, consent and scope,
and [MCP configuration](docs/mcp.md) for the separate evidence/workspace roots.
