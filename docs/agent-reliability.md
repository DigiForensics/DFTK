# Agent workflow reliability

DFTK is the primary install entry point; the companion DFTK-skill bundle makes
it the default examination runtime for authorized forensic tasks. The runtime
executes structured examinations; the Agent remains responsible for scope,
evidence requirements, corroboration, and conclusions.

## Bootstrap behavior

`dftk agent setup` generates JSON/TOML entries using the active Python executable
with `-m dftk`. This avoids reliance on a desktop host inheriting a shell PATH.
The environment must remain installed at that path; rerun setup if it moves.
Setup enables `<workspace>/audit.jsonl` by default and rejects config/audit outputs
inside the evidence root. Installation and doctor share one host detector and
respect `CODEX_HOME` for Codex Skill locations. The complete Skill bundle is
installed; incomplete bundles, source/destination overlap, and bundle symlinks
are rejected. Global host configuration still uses the host's normal import and
trust workflow.

## Operational coverage

Use `dftk_case(action="coverage")` or `dftk case ... coverage <case_id>` before
conclusions. The report contains run status counts, warnings/errors, unreadable
artifacts, stored-result digest checks, and pending analysis. Failed/partial
routes remain review actions. Brief checkpoints retain later failures even after
the highlight budget is filled. JSON and Markdown exports include operational
coverage.

`no_recorded_limitations` is a statement about recorded execution history. It
never proves full acquisition, complete parser support, or absence of activity.
An older run without a stored digest has limited integrity assurance. Historical
failed runs stay visible even after a successful retry and require contextual
review. Coverage's next-action list is bounded by the ordinary Case action queue.

Intake reports attempted and successful inspections separately, per-file failure
status, extension hints versus signature identification, and traversal exclusions.
File search reports unreadable/oversized files and traversal/result limits as
partial coverage, with hashes of matched input bytes. Evidence previews can be
shorter than full candidate/match facts; omitted counts make this explicit.

## SQLite interpretation

The forensic byte parser distinguishes integer constants 0/1 from empty text and
empty BLOB values. WAL validation includes the header checksum, salt/checksum
chain, and commit boundary. Reconstruction overlays only the contiguous valid
prefix ending at its last commit and honors the committed database size. Corrupt,
uncommitted, or truncated tails are excluded and reported. These rules follow
[SQLite's record and WAL format specification](https://www.sqlite.org/fileformat.html).

`database.sqlite_recover` exposes bounded live records separately from heuristic
carved candidates. BLOB columns use `{type: "blob", hex: "...", length: N}` for
lossless JSON transport. Columns are raw stored record values with a separate
rowid; SQL defaults, affinity, and INTEGER PRIMARY KEY aliases are not expanded.
Counts exclude explicitly listed unsupported roots, including WITHOUT ROWID and
virtual tables. Record-start page/frame locators and DB/WAL hashes identify
reconstruction inputs; they do not independently authenticate acquisition origin.

Immutable database/browser tools warn when sidecars can hold excluded state.
Preserve DB/WAL/journal inputs and use a committed reconstruction for recent
transaction evidence. Never checkpoint the original evidence to make a parser
work. Deleted carving remains heuristic; zero candidates cannot prove deletion
never occurred.

## Perception and continuity

Media discovery retains unreviewed items beyond the first signature-inspection
window. Metadata, pixel disclosure, OCR and analyst disposition are distinct
records. Preview/contact-sheet gates precede decoding; persisted Case JSON does
not replay image pixels. Native MCP transport is tested with an actual client,
including Python 3.10 result-schema behavior.

Batch OCR shares model initialisation, preserves per-source hashes/outcomes and
returns unattempted paths on a cooperative budget/backend failure. No GPU failure
causes an implicit CPU retry. Cooperative limits do not guarantee durable partial
results if a process is killed during inference.

One supplied OpenSSL candidate can produce a structurally validated derivative;
that derivative can be inventoried/extracted and parsed under the same Case.
Root-aware source access checks exact registered paths and hashes, rejecting
unregistered/altered workspace inputs. Password values are redacted from Case
run/attempt parameters, including credentials that resemble paths.

## Executable validation

With development requirements installed, run relevant fixture checks:

```bash
python -m pytest tests/test_agent_reliability.py tests/test_sqlite_committed_snapshot.py -q
python -m pytest tests/test_media_perception.py tests/test_perception_workflows.py tests/test_mcp_native.py -q
python -m pytest -q --cov=dftk --cov-report=term --cov-fail-under=60
python scripts/check_docs.py
```

| Area | Observable invariant |
|---|---|
| Bootstrap | Generated configuration uses the actual interpreter, survives an empty PATH and preserves audit/root choices |
| Installation | Complete main/specialist trees and rebased references; reject overlap, incomplete bundles and symlinks |
| Discovery/access | Actual inspection successes versus attempts, source/window hashes, limits and traversal exclusions |
| MCP protocol | Real tool discovery, Case flow, native images/contact sheets and structured results across supported Python versions |
| Consent/OCR | No pixel decode before attestations, no unapproved CPU start/fallback, per-source boxes and resumable batch outcomes |
| Derivatives | OCR clue to one-candidate decrypt/extract/query, structural validation, unchanged sources and rejected altered outputs |
| Case recovery | Retain late failures and interrupted attempts; detect changed/unreadable stored results |
| SQLite/WAL | Compare stored values/committed reconstruction with engine-generated fixtures; reject invalid/uncommitted tails |

Mocks exercise dispatch/failure decisions, not actual GPU performance. A synthetic
real-MPS check during 3.7.0 development recognised two images, used one observed
candidate to decrypt a ZIP and queried its SQLite member with unchanged source
hashes. That one fixture is not a benchmark for other hardware, CUDA, difficult
image quality, malicious input or real-case recall.

CI covers Python 3.10–3.13 with development requirements. Optional oracles/engines
may be absent and their tests skipped; inspect skip reasons. Host routing is
tested using isolated markers/configuration, not every real desktop UI. Regression
coverage is not forensic accuracy, acquisition completeness or an industry ranking.
