# MCP configuration and contract

DFTK 3.7.0 exposes eight meta-tools over local stdio. An MCP host launches the
process and exchanges JSON-RPC through stdin/stdout; there is no HTTP endpoint or
listening port. Registry capabilities execute in isolated worker processes.

## Install and launch

```bash
python -m pip install --upgrade "dftk[mcp]"
dftk mcp --root /evidence/acquisition --workspace /cases/investigation --check
dftk mcp --root /evidence/acquisition --workspace /cases/investigation --audit
```

The evidence directory must exist. `--check` validates startup without serving
MCP and may create the workspace. Use [Agent setup](../INSTALL_AGENT.md) to install
the companion Skill and generate interpreter-bound configuration fragments.

| Launch option | Default | Effect |
|---|---|---|
| `--root DIR` | Current directory | Source evidence scope; choose it explicitly |
| `--workspace DIR` | `$DFTK_WORKSPACE` or `~/.dftk` | Writable Case/derived area, outside the evidence root by default |
| `--max-safety` | `READ_ONLY` | Accepts READ_ONLY or STATEFUL; not DESTRUCTIVE |
| `--allow-network` | Off | Permits capabilities declaring network access |
| `--timeout SECONDS` | 180 | Worker deadline, clamped to 1–3600 seconds |
| `--audit [PATH]` | Off | Enables the ledger; a bare flag uses `<workspace>/audit.jsonl`; relative paths resolve under workspace |
| `--allow-workspace-in-root` | Off | Explicit compatibility exception; derived writes then enter the acquired tree |

The process owner controls these settings. MCP arguments cannot raise the safety
ceiling, enable network or change the roots. Case persistence can write the
workspace even when the capability ceiling is READ_ONLY.

## Host configuration

Prefer `dftk agent setup --config-out ...` and import its `mcp_json` or
`codex_toml` output. For a manually managed JSON host, merge a fragment such as:

```json
{
  "mcpServers": {
    "dftk": {
      "command": "/opt/dftk-env/bin/python",
      "args": ["-m", "dftk", "mcp", "--root", "/evidence/acquisition", "--workspace", "/cases/investigation", "--audit"]
    }
  }
}
```

Replace the interpreter with the real installation path; on Windows it normally
ends in `Scripts\python.exe`. A desktop host may not inherit your terminal PATH.
Keep the environment installed, enable/approve the server according to the host,
and refresh the session after changing code or configuration. Installing the
Skill alone does not expose MCP tools.

## Tool surface

| Meta-tool | Contract |
|---|---|
| `dftk_doctor()` | Dependencies/readiness plus server root, workspace, safety, network and timeout |
| `dftk_search_capabilities(query="", tags=None, produces=None, limit=12)` | Search registered capabilities; readiness and policy eligibility are separate |
| `dftk_suggest(query, direction="consume", limit=12)` | Explained input hints or declared output matches; consume probes only root-confined regular files |
| `dftk_describe(name)` | Exact parameters, path roles, safety, dependencies and output types |
| `dftk_run(name, params=None, case_id=None)` | Execute a registry capability, optionally persisting it |
| `dftk_view_media(...)` | Single image/crop, contact sheet or sampled video frames as native MCP images |
| `dftk_case(action, ...)` | Case creation/list/show, artifacts/dispositions, optional intake, context/coverage and correlation/export |
| `dftk_read_case_run(case_id, seq, ...)` | Page an existing Observation without executing a parser |

Capability names such as `media.ocr` belong in `dftk_run(name=...)`, not directly
in a protocol call. `dftk_describe` describes capabilities, not the meta-tools.

### Cases and paging

Case actions are `new`, `list`, `show`, `artifacts`, `note_artifact`,
`guided_intake`, `next`, `brief`, `coverage`, `timeline`, `graph` and `export`.
Retain the generated ID. `guided_intake` accepts `path`, optional `objective` and
`max_steps` (0–5, default 2). Direct tool composition is equally supported.

`artifacts` uses `offset`/`limit`; `note_artifact` needs the recorded absolute
`path`, a reason and one of `reviewed`, `deferred`, `user_declined`,
`model_unsupported`, `not_relevant`. These are analyst assertions.

Large JSON replies are bounded to approximately 512 KiB. Full Case-scoped results
remain on disk. Follow `case_run.seq` and page:

```text
dftk_read_case_run(case_id="CASE_ID", seq=3, evidence_offset=0, evidence_limit=20)
dftk_read_case_run(case_id="CASE_ID", seq=3,
                   fact_path="/browser.chromium_history/visits", value_limit=20)
dftk_read_case_run(case_id="CASE_ID", seq=3, section="meta",
                   fact_path="/provenance/artifacts", value_limit=20)
dftk_read_case_run(case_id="CASE_ID", seq=3, section="derived_artifacts", value_limit=20)
```

`fact_pointers` exposes addresses. JSON Pointer escapes `/` as `~1` and `~` as
`~0`; dotted capability names stay one key. The default reader omits bulky child
Observations/provenance metadata, which can be paged explicitly. A direct run
without a Case has no persisted full result to recover.

### Images and OCR

`dftk_view_media` accepts exactly one of `path` or `paths`. Single inputs accept
`crop_box` and `max_dimension`; video uses `start_seconds`, `interval_seconds` and
`frame_count` (up to 8). `paths` produces a numbered contact sheet of up to 16
still images. Both `user_authorized` and `model_supports_images` default false.

Only set them after scoped user consent and confirmed model image support.
Without either, report discovered media without pixels. Native images are
transport-only and are not replayed from Case JSON. Pixels use a separate bounded
payload, not base64 embedded in the structured result.

Local OCR runs through `media.ocr` / `media.ocr_batch` and uses provisioned weights.
GPU first; CPU needs a separate affirmative decision. Read the full
[media contract](media-perception.md) for coordinates, models, video scope and budgets.

## Paths and derived evidence

| Declared role | Accepted scope |
|---|---|
| `EVIDENCE_INPUT` | Evidence root, or exact Case-registered workspace files whose digests still match |
| `WORKSPACE_OUTPUT` | Workspace; paths inside acquired evidence are refused |
| `WORKSPACE_INPUT` | Workspace inputs |
| `ANALYSIS_INPUT` | Evidence/workspace analysis material such as Observations, rules and seals |

Relative source inputs resolve under the evidence root; relative outputs under
the workspace. Directory browsing may list workspace metadata; that does not
authorise arbitrary workspace files as evidence inputs. Reuse the same Case for
decryption/extraction and follow-up parsing. Recipes inherit the parent policy.
Opaque filesystem-internal paths are not host paths.

## Read results correctly

For an executed capability, `ok: true` means Observation status `ok` or `partial`.
Read warnings/errors and scope in both cases. `ok: false` may still carry useful
partial facts or derived files; inspect what was actually completed. A preflight,
unknown-capability, policy or worker failure can return a top-level status/error
without an Observation. Worker interruptions are retained in Case attempts.

Successful execution, source hashes and `no_recorded_limitations` do not establish
complete acquisition or absence of activity. [Safety model](../SAFETY.md)

## Troubleshooting

| Symptom | Check |
|---|---|
| Tools absent | Host entry enabled/approved, correct interpreter, fresh session; run the same command with `--check` |
| MCP dependency missing | Install `dftk[mcp]` in the interpreter actually launched; supported SDK range is `>=2.0.0,<3` |
| Workspace rejected | Choose a separate writable directory outside source evidence |
| STATEFUL operation blocked | Authorised host owner must relaunch with `--max-safety STATEFUL`; an MCP argument cannot change it |
| Derived input rejected | Same Case ID, exact registered path, file present and unchanged digest |
| OCR unavailable | Check extra, GPU/runtime compatibility, local weights and MPS fallback settings; do not silently enable CPU |
| Preview denied | Check consent scope and actual image support; do not bypass through another tool |
| Timeout/truncated result | Inspect attempts, use smaller bounded work and page completed Case results |
