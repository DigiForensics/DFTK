# Agent integration

DFTK supplies evidence access, perception, bounded operations and persistent
results. The host Agent owns investigation objectives, scheduling, hypotheses,
corroboration and conclusions. The companion Skill teaches those decisions; it
does not add parsers or a separate autonomous runtime.

## Installation and configuration

Follow [INSTALL_AGENT.md](INSTALL_AGENT.md) for the runtime/Skill bootstrap.
`dftk agent setup --install-skill` selects the Skill tag matching the installed
runtime, installs the full resource tree and emits a portable JSON fragment plus
Codex TOML. It does not edit global host configuration. The generated command
binds the active Python executable and enables a workspace audit ledger.

The host owner chooses the evidence root, separate workspace, safety ceiling,
network access and timeout. Default READ_ONLY permits source reads and Case
persistence; five registered STATEFUL capabilities write derived workspace files.
An Agent cannot loosen the server policy through a tool argument.

## Eight MCP entry points

| Entry point | Use |
|---|---|
| `dftk_doctor` | Inspect runtime dependencies and the active server policy |
| `dftk_search_capabilities` | Search by evidence need, tags or produced types; Chinese aliases are supported |
| `dftk_suggest` | Explain candidates from a source name/kind, or find declared outputs with `produce` |
| `dftk_describe` | Read the exact registered capability contract |
| `dftk_run` | Execute one capability and optionally persist it in a Case |
| `dftk_view_media` | Return native image/crop/contact-sheet/video-frame content under scoped consent |
| `dftk_case` | Manage Case context, inventory, dispositions, coverage and correlation/export views |
| `dftk_read_case_run` | Page persisted facts/evidence/provenance without executing the parser again |

These are protocol tools. Names such as `database.sqlite_query` or `media.ocr`
are registry capabilities passed to `dftk_describe` / `dftk_run`, not extra MCP
tools. [Full MCP contract](docs/mcp.md)

## Compose work around evidence gaps

Create a Case when related operations need persistence; retain the returned ID.
Browse directories, inspect an artifact, read contextual text or call a specialist
parser according to the question. `evidence.intake` is useful for a bounded source
manifest. `guided_intake` optionally persists intake plus a few read-only child
operations. `next` returns capability hints, not a compulsory task queue.

```text
dftk_case(action="new", name="investigation")
dftk_run(name="evidence.browse", params={"path":"."}, case_id="CASE_ID")
dftk_run(name="file.read_text", params={"path":"notes.txt"}, case_id="CASE_ID")
```

Reuse known contracts and prior observations. Search/describe when selecting an
unfamiliar capability; do not repeatedly discover a tool whose contract is already
known. Suggestions expose readiness and policy eligibility separately; neither
guarantees that a particular input is supported.

## Perception and authorisation

Discovery/metadata are separate from visual review. Before pixels reach a model,
confirm image support and user consent for that file/scope. Without either, report
the media and preserve an unreviewed item. The host supplies the consent/model
attestations; DFTK cannot inspect chat consent itself.

`dftk_view_media` accepts a single `path` (optional source-coordinate `crop_box`, or
timestamped video samples) or `paths` for up to 16 still-image thumbnails. Local
`media.ocr` / `media.ocr_batch` are independent of model vision. They select
CUDA/MPS; no GPU or GPU failure requires a user decision before slow CPU execution.
Batch OCR shares model loading and returns `remaining_paths` when its cooperative
budget or backend failure stops further inputs. [Media limits](docs/media-perception.md)

## Act on a source-backed lead

Encrypted content is one evidence branch. Preserve readable members and continue
independent evidence. ZIP extraction accepts one supplied password. OpenSSL
decryption accepts one candidate plus explicit cipher/KDF/expected-format settings
and a credential-source reference. Neither generates guesses. Equivalent calls
are not globally prevented: scheduling and attempt budgets remain with the Agent.

Use the same Case for extraction/decryption and follow-up analysis. Exact derived
workspace paths are registered with digests; evidence-input tools can consume them
after validation. Arbitrary workspace files or changed outputs do not gain source
access merely by existing under the workspace.

## Read, recover and report

- Read `observation.status`, warnings and errors even when `ok` is true; `partial`
  can contain useful evidence and known omissions. A policy/startup failure may
  return a top-level status/error without an Observation.
- Persist large results in a Case. Follow result pointers and pagination rather
  than rerunning a parser. Case recovery returns metadata, not prior image pixels;
  further disclosure needs valid in-scope consent.
- Use `artifacts` to page evidence memory. `note_artifact` records an analyst
  disposition with a reason; it does not prove that the content was examined.
- Use `brief` to recover context and `coverage` before negative findings/final
  reporting. Unread items, interrupted attempts and historical failures remain
  visible. Review them against the question.
- Request graph/timeline views when they help a claim. Exported summaries and
  hash integrity are not proof of attribution or complete acquisition.

MCP confines DFTK calls; it does not sandbox unrelated shell tools, enforce a
read-only OS mount, prevent every parser exploit or establish evidence truth.
See [safety](SAFETY.md) and [reliability evidence](docs/agent-reliability.md).
