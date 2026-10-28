# User guide

Use MCP for host-enforced DFTK root/policy/deadline controls, the CLI for local
automation and Python for application integration. CLI/Python callers must choose
their own source/workspace scope; an MCP configuration does not constrain them.
Commands below use POSIX shell quoting and example absolute paths.

## Discover and run

```bash
dftk --version
dftk doctor
dftk list --group
dftk suggest /evidence/acquisition/History
dftk suggest tls_sni --direction produce
dftk search "图片文字识别"
dftk describe database.sqlite_query
dftk run artifact.inspect --params '{"path":"/evidence/acquisition/sample.bin"}'
```

Descriptions expose parameters, safety, network, path roles, dependencies and
outputs. `suggest` gives heuristics rather than parsing proof; `produce` matches
declared output kinds without reading files. Dependency discovery and policy
eligibility do not establish whether a specific input will parse.

`run TOOL INPUT` can map a positional input to the primary parameter. Explicit
`--params` is clearer for multi-input tools; `--params-file /cases/params.json`
avoids shell-specific JSON quoting and secrets in command-line arguments.
Protect parameter files, since they can contain credentials.

## Interpret Observations

An Observation contains `tool`, `status`, `summary`, `facts`, `evidence`,
`warnings`, `errors`, `meta` and `derived_artifacts`. It does not have MCP's
top-level `ok` flag. Evidence can include a source, record/byte locator, raw value,
hash, method, confidence and derivation reference.

| Status | Meaning | CLI capability exit code |
|---|---|---|
| `ok` | Operation completed within its declared scope | 0 |
| `partial` | Useful results with omissions, warnings or incomplete work | 0 |
| `unsupported` | Format, dependency or operation unavailable | 2 |
| `blocked` | Policy or required consent prevented work | 2 |
| `error` | Invalid parameters, parsing or execution failure | 1 |

Errors can coexist with recovered evidence. Never turn failure, truncation, zero
matches or empty OCR into an unqualified negative finding. Read the tool's facts
and limits before consuming its result.

## Browse and read context

```bash
dftk run evidence.browse --params '{"path":"/evidence/acquisition","offset":0,"limit":100}'
dftk run file.read_text --params '{"path":"/evidence/acquisition/notes.txt","offset":0,"length":16384}'
```

Follow `next_offset`. Text windows use byte offsets, not line numbers; select the
encoding explicitly when needed. A window hash identifies returned bytes and is
not necessarily a full-file hash. Browse lists metadata without decoding media;
`file.read_text` rejects identified media rather than acting as visual review.

## Cases

The default workspace is `$DFTK_WORKSPACE` or `~/.dftk`, not a directory inside
the current evidence tree. Set it explicitly for repeatable work:

```bash
dftk case --workspace /cases/investigation new --name investigation
dftk case --workspace /cases/investigation run CASE_ID evidence.intake --params '{"path":"/evidence/acquisition"}'
dftk case --workspace /cases/investigation artifacts CASE_ID --offset 0 --limit 100
dftk case --workspace /cases/investigation brief CASE_ID
dftk case --workspace /cases/investigation coverage CASE_ID
dftk case --workspace /cases/investigation export CASE_ID --format md --out /cases/investigation/report.md
```

Use the ID from `new`. Cases live under `<workspace>/cases/<id>/`, with a manifest
and per-run Observation JSON. Reuse observations instead of reparsing for display.
MCP offers paged facts/evidence/provenance through `dftk_read_case_run`; CLI users
can inspect the stored artifacts. [MCP paging](mcp.md)

Intake and registered outputs populate artifact memory. Record a disposition with
an explicit reason when review is complete, declined, deferred or irrelevant:

```bash
dftk case --workspace /cases/investigation note-artifact CASE_ID /evidence/acquisition/photo.png --disposition deferred --reason "Awaiting scoped visual-review consent"
```

This is an analyst assertion, not verification of viewing. Coverage retains unread
items, interrupted attempts, partial/failed runs and integrity limits. Optional
`guided-intake` persists a bounded first pass; `next` recommends known actions.
Neither is required for every investigation.

### Nested evidence and STATEFUL work

`archive.extract_safe`, `crypto.openssl_decrypt`, `filesystem.extract`,
`network.http_sessions` and `case.report_html` are STATEFUL. The default blocks them.
For an authorised extraction:

```bash
dftk case --workspace /cases/investigation run CASE_ID archive.extract_safe --max-safety STATEFUL --params '{"path":"/evidence/acquisition/backup.zip","output_dir":"/cases/investigation/unpacked"}'
```

In root-aware MCP/Python Cases, exact derived paths and hashes allow later source
parsers to consume registered workspace output. Use the same Case and returned
paths. CLI Case calls do not themselves supply the MCP evidence-root confinement;
keep outputs outside evidence and use explicit absolute paths.

### Findings and correlation

CLI/Python findings cite persisted evidence indices, using statuses VERIFIED,
SUPPORTED, CANDIDATE, UNRESOLVED or UNSUPPORTED. These are analyst conclusion labels,
distinct from Observation status:

```bash
dftk case --workspace /cases/investigation finding CASE_ID --claim "Observed source hash" --status SUPPORTED --citations '[{"run_seq":1,"evidence_index":0}]'
dftk case --workspace /cases/investigation findings CASE_ID
dftk case --workspace /cases/investigation graph CASE_ID
dftk case --workspace /cases/investigation timeline CASE_ID
```

The finding example assumes run 1 really contains the cited hash evidence; choose
the actual indices and claim. `timeline.hunt_sequences` supports bounded ordered
event-chain correlation; see [its contract](sequence-hunting.md). Entity matches
and timeline proximity require interpretation before attribution.

## Images, video and OCR

Use native MCP media tools to send images to an authorised image-capable model.
CLI JSON does not transport preview pixels as model images. Local OCR is available
through either interface:

```bash
dftk run media.ocr --params '{"path":"/evidence/acquisition/screen.png","languages":["ch_sim","en"]}'
```

Install the extra, GPU runtime and weights before examination. Batch OCR uses one
model initialisation and returns per-file outcomes/continuation. CPU needs its own
affirmative consent. Video uses sampled frames only. [Perception guide](media-perception.md)

## Audit and integrity

CLI: add `--audit /cases/investigation/audit.jsonl`, or set `DFTK_AUDIT_LOG` for
registry executions. Agent setup enables a ledger in generated MCP configuration;
direct MCP launch requires `--audit`. The ledger records DFTK registry operations,
not arbitrary shell commands, host-model reasoning or other applications.

```bash
dftk audit verify /cases/investigation/audit.jsonl
dftk audit seal /cases/investigation/audit.jsonl
dftk audit verify /cases/investigation/audit.jsonl --seal /cases/investigation/audit.jsonl.seal.json
```

Verification exits 0 for an intact supported chain, 1 for reported defects and 2
for unreadable input. Read the verdict/details. Store seals independently: an
unanchored hash chain cannot establish that a rewritten ledger is authentic, and
tail deletion needs an external reference. Audit failure does not turn a parser
result into a failure; check audit health separately. Redaction is not a guarantee
that all sensitive content has disappeared from reports/Observations.

Most JSON/report outputs refuse replacement without `--force`; tool-specific
workspace writers have their own overwrite rules. Choose every output outside
source evidence. [Safety](../SAFETY.md)

## Python integration

```python
from pathlib import Path
import dftk

policy = dftk.SafetyPolicy(
    evidence_root=Path("/evidence/acquisition"),
    workspace_root=Path("/cases/investigation"),
)
result = dftk.run_tool("artifact.inspect", {"path": "sample.bin"}, policy=policy)
print(result.to_dict())
```

`get_registry()` and `run_tool()` are public entry points. For persistence use
`dftk.core.case.CaseSession`, supplying roots when a bounded policy is needed.
Python calls do not automatically acquire the MCP process deadline. See
[architecture](../ARCHITECTURE.md) and [reliability validation](agent-reliability.md).
