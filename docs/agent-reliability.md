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

## Executable validation

Run:

```bash
python -m pytest tests/test_agent_reliability.py tests/test_sqlite_committed_snapshot.py -q
python -m pytest -q --cov=dftk --cov-report=term --cov-fail-under=60
python scripts/check_docs.py
```

The focused tests check observable behavior:

| Area | Validation |
|---|---|
| Desktop bootstrap | Launch generated config using the actual interpreter with empty PATH and paths containing spaces |
| Installation | Reject incomplete/recursive bundles; preserve full Skill tree and rebased references |
| Intake/search | Report inspection failures, traversal denial, symlink exclusions, bounds, and exact matched-byte hashes |
| MCP boundaries | Reject out-of-root guided intake and child routes; preserve audit and use timeout worker |
| Agent protocol | Real stdio initialization, tool discovery, Case creation, guided intake, coverage, and persisted-result paging |
| Recovery/resume | Retain late failures when highlights fill; detect unreadable/replaced/tampered result artifacts |
| SQLite values | Compare raw byte-parser values with SQLite engine output, including integer 0/1 and empty BLOB/text |
| WAL snapshot | Compare reconstruction with an engine-generated committed database; reject uncommitted/corrupt/truncated tails |
| Source preservation | Compare acquired DB/WAL file sets and bytes before and after Case examination |

Tests establish these invariants on their fixtures. They do not certify every
format, every optional parser, real evidence of unknown quality, or a host UI's
installation/discovery behavior. WorkBuddy/Codex host routing is exercised through
isolated markers and install plans; real MCP transport is exercised independently
of those desktop UIs. Test coverage is a regression indicator, not forensic
accuracy or a claim of industry leadership.
