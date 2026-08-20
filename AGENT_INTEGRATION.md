# Agent integration

DFTK is the single entry point for an investigation Agent. It supplies the runtime,
the local MCP server, and the matching `DFTK-skill` bundle. Give an Agent this URL:

```text
https://github.com/DigiForensics/DFTK
```

The Agent must not need a separate `DFTK-skill` repository URL.

## One-command bootstrap

Install the runtime with MCP support, then let the Agent prepare a bounded
integration. The evidence directory is read-only input; the case workspace is a
different writable directory.

```bash
python -m pip install --upgrade "dftk[mcp]"
dftk agent setup \
  --root /evidence/2026-001 \
  --workspace /cases/2026-001 \
  --install-skill \
  --config-out /cases/2026-001/dftk-agent-config.json
```

`agent setup` creates the case workspace, installs the release-matched Skill into
the detected Agent Skills location, and writes a reviewable MCP configuration
artifact. It never edits a host's global MCP configuration without the host owner's
explicit import/approval. This prevents unrelated MCP entries from being replaced.

Start with a dry run when an Agent needs to explain its actions first:

```bash
dftk agent setup --root /evidence/2026-001 --workspace /cases/2026-001 --dry-run
```

The JSON artifact includes a portable `mcpServers.dftk` fragment and `codex_toml`.
Import the appropriate fragment using the MCP host's normal UI or configuration
workflow, approve the local server, then start a new Agent session. Validate the
exact launch policy before connecting:

```bash
dftk mcp --root /evidence/2026-001 --workspace /cases/2026-001 --check
```

For Codex, add the generated `codex_toml` block to its MCP configuration. For any
JSON-configured MCP host, merge `mcp_json.mcpServers.dftk`; its launch command is
always `dftk mcp --root <root> --workspace <workspace> ...`.

## Agent operating loop

After the host exposes DFTK, the Agent follows a small, recoverable tool loop:

1. Call `dftk_doctor` and state the active root, safety, network, and timeout policy.
2. Create a case with `dftk_case(action="new")`.
3. Use `dftk_case(action="guided_intake", path=..., case_id=...)` for the first
   bounded pass. It preserves the intake manifest and child observations separately.
4. Use `dftk_case(action="next")`, then `dftk_search_capabilities` and
   `dftk_describe` before every new capability choice.
5. Run the chosen capability with `dftk_run(..., case_id=...)`. Branch on `ok`; do
   not turn an `unsupported`, `blocked`, or `error` result into a finding.
6. Before handing off or recovering context, call `dftk_case(action="brief")` and
   `dftk_case(action="graph")`. Export only after reviewing the timeline.

Use `dftk_read_case_run` to page a persisted observation rather than rerunning a
tool merely to recover its output.

## Boundaries the Agent must preserve

- The MCP process owner selects `--root`, `--workspace`, safety, network, timeout,
  and audit settings. The model cannot loosen them through a tool call.
- `READ_ONLY` and network-disabled are the default. Raise to `STATEFUL` or add
  `--allow-network` only with explicit authorization.
- Add `--audit /cases/2026-001/audit.jsonl` when a chain-of-custody execution log is
  required.
- DFTK confines its own MCP parameters, but it cannot restrict unrelated shell or
  filesystem tools granted to the host Agent. Keep those permissions narrower than
  the evidence scope.

## Manual skill installation

The bootstrap command is preferred. For an existing host setup, install the matching
bundle directly:

```bash
dftk skill --install                 # detects one active host, else ~/.agents/skills
dftk skill --install --target codex  # explicit target
dftk skill --install --target all --dry-run
```

See [docs/mcp.md](docs/mcp.md) for server policy and troubleshooting, and
[INSTALL_AGENT.md](INSTALL_AGENT.md) for the short instruction intended to be pasted
into an Agent task.
