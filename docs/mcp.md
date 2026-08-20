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
| `dftk_case` | create, inspect, return deterministic next actions, correlate timelines/entities, and export cases |
| `dftk_read_case_run` | page a persisted observation |

For `dftk_run`, `ok: true` means the observation status is `ok` or `partial`.
When `ok` is false, inspect `observation.status` and `observation.errors` before
choosing another capability or adjusting the server policy.

The [DFTK-skill MCP reference](https://github.com/DigiForensics/DFTK-skill/blob/main/references/mcp-setup.md)
contains host configuration examples and troubleshooting details.
