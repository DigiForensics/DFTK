# MCP guide

## Start the server

Install the optional dependency, then start the server from or with an explicit
authorized evidence root:

```bash
pip install "dftk[mcp]"
dftk mcp --root /evidence/acquisition --workspace /cases/intake --check
dftk mcp --root /evidence/acquisition --workspace /cases/intake --max-safety READ_ONLY --timeout 180
```

The server uses stdio. Configure an MCP host to launch `dftk mcp` with the selected
root and policy options.

## Agent bootstrap

For a new Agent, prefer the primary DFTK bootstrap over manually copying a Skill or
hand-writing a server entry:

```bash
dftk agent setup \
  --root /evidence/acquisition \
  --workspace /cases/intake \
  --install-skill \
  --config-out /cases/intake/dftk-agent-config.json
```

The command installs the matching DFTK-skill release and emits both a portable JSON
`mcpServers.dftk` fragment and a Codex TOML fragment. Import one through the host's
normal configuration flow, approve it, then start a fresh Agent session. It does not
overwrite a host's global MCP configuration. Run with `--dry-run` to review the
planned workspace, Skill target, and launch command before any write.

## Policy

The server defaults to `READ_ONLY` with network access disabled. `--root` is the
read scope for source evidence; `--workspace` is a separate writable location for
cases, locks, and audit records. The process owner, not an MCP caller, controls
`--root`, `--workspace`, `--max-safety`,
`--allow-network`, `--timeout`, and `--audit`.

| Tool | Purpose |
|---|---|
| `dftk_doctor` | runtime and policy information |
| `dftk_search_capabilities` | find capabilities by evidence need |
| `dftk_describe` | inspect a capability contract |
| `dftk_run` | execute and optionally persist an observation |
| `dftk_view_media` | consent-gated native image previews, source-coordinate crops, contact sheets and timestamped video samples |
| `dftk_case` | create, inspect, return deterministic next actions, correlate timelines/entities, and export cases |
| `dftk_read_case_run` | page a persisted observation |

For `dftk_run`, `ok: true` means the observation status is `ok` or `partial`.
When `ok` is false, inspect `observation.status` and `observation.errors` before
choosing another capability or adjusting the server policy.

The [DFTK-skill MCP reference](https://github.com/DigiForensics/DFTK-skill/blob/main/references/mcp-setup.md)
contains host configuration examples and troubleshooting details.

## Capability suggestions and path roles

`dftk_suggest` adds an explained input/output discovery entry point. The server now
exposes eight meta-tools. `consume` performs bounded header probes under the evidence
root; `produce` matches declared output kinds without file reads. Policy eligibility
only covers safety/network gates. Confirm dependency readiness and the contract.

Every registered host-path parameter has a path role. Output paths resolve under
the writable workspace; analysis inputs (Observation files/rules/seals) can be read
under evidence or workspace roots. Opaque paths inside a disk image are not host
paths. Child recipe runs inherit the server's policy.

## Perception, OCR and evidence memory

See [media perception](media-perception.md) for consent, local OCR and video
sampling. `dftk_view_media` requires explicit scoped user consent and confirmed
model image support; both flags default false. Otherwise report found media
without pixels. Local GPU OCR is separate; CPU execution requires its own
affirmative consent after explaining that it may be very slow.
Use `paths` instead of `path` for a numbered still-image contact sheet; use
`crop_box` with a single image for detail. `media.ocr_batch` shares model loading,
keeps per-file outcomes and returns `remaining_paths` at its cooperative budget.
`crypto.openssl_decrypt` performs one evidence-backed attempt with explicit
parameters and validates the inner format before registering its workspace output.

`evidence.browse` pages directories; `file.read_text` returns bounded text windows.
Case `artifacts` pages source/derived evidence memory; `note_artifact` records an
Agent disposition while retaining declined/deferred coverage gaps. Case-registered
derived files may be read under the workspace after digest validation; arbitrary
workspace files remain blocked.

Case-run `fact_path` accepts JSON Pointers, including keys containing dots, without
duplicating child metadata. Timed-out executions remain visible in
`coverage.interrupted_attempts` even without a completed Observation.
