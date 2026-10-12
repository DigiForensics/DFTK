# Agent integration

DFTK 3.5.0 provides two Agent-facing interfaces:

1. the complete `DFTK-skill` investigation guidance;
2. native local stdio MCP backed directly by DFTK Registry / Observation / CaseSession.

The MCP server is deliberately local and stdio-only in 3.5.0.

## Recommended agent loop

The toolkit is designed to be driven by an LLM Agent, not a human at a prompt.
The intended call sequence is:

1. `dftk_doctor` — confirm the runtime, optional extras, and the server-owned
   safety/root policy before doing anything.
2. `dftk_suggest` — the Agent entry point. Hand it an evidence **path**
   (`/cases/2026-001/capture.pcap`), a bare forensic **filename** (`$MFT`,
   `Amcache.hve`), or an evidence **kind** (`tls`, `registry`, `memory`). It
   returns the ranked capabilities that apply, each with a `why` string, so the
   Agent can justify its choice instead of guessing. Use `direction='produce'`
   to find tools declaring a required output kind (for example `tls_sni`).
3. `dftk_describe` — read the exact parameter / safety / dependency contract for
   the chosen capability before calling it.
4. `dftk_run` — execute, optionally persisting into an existing case.
5. `dftk_read_case_run` — page the resulting Observation (evidence / facts) when
   it is too large for a single response.

This loop keeps the Agent inside the server-owned safety/root/network policy: it
never sets `--allow-network` or a higher `--max-safety` itself; those are
server-owner switches.

## Install

```bash
pip install "dftk[mcp]"
dftk doctor
dftk skill --install
```

For optional forensic parsers plus MCP:

```bash
pip install "dftk[all]"
```

`dftk[all]` still does not provide specialist system bindings such as `pyewf` / `pytsk3` where those require a dedicated forensic environment.

## Environment preparation (external forensic tools)

DFTK discovers external binaries (jadx, apktool, tshark, ghidra, radare2, …) but
does not execute them. When you also ship a forensic-toolkit zip, the recipient
extracts it and runs:

```bash
dftk prepare <extracted_toolkit_root>
```

This records the toolkit root + a DFTK-managed shim directory in
`~/.dftk/toolchain.json` and generates launchers, so the tools are found on every
subsequent `dftk` call without editing PATH — and remain readable by the agent
even when the toolkit lives on an exotic / non-PATH drive. See
`DEPLOY-TOOLCHAIN.md` for the recipient guide and fallbacks.

## Start policy

Run the server with the narrowest authorized evidence root:

```bash
cd /cases/2026-001
dftk mcp
```

Equivalent explicit form:

```bash
dftk mcp \
  --root /cases/2026-001 \
  --workspace .dftk \
  --max-safety READ_ONLY \
  --timeout 180
```

Only a human/server owner should opt into network or the single STATEFUL capability class:

```bash
dftk mcp --root /cases/2026-001 --max-safety STATEFUL
# or, only when authorized:
dftk mcp --root /cases/2026-001 --allow-network
```

The model cannot pass those policy switches through `dftk_run`.

To keep a chain-of-custody record of everything the Agent executed, add `--audit`:

```bash
dftk mcp --root /cases/2026-001 --audit                       # .dftk/audit.jsonl
dftk mcp --root /cases/2026-001 --audit /cases/2026-001/audit.jsonl
```

Each capability run the Agent triggers appends one JSONL line (timestamp, tool, caller, parameters with secrets masked, safety level, status, evidence hashes, errors). Like the policy switches, this is a server-owner setting and not a model-callable argument.

## Kimi Code

Kimi supports project-level `.kimi-code/mcp.json` and stdio MCP. Example:

```json
{
  "mcpServers": {
    "dftk": {
      "command": "dftk",
      "args": ["mcp", "--root", "."],
      "startupTimeoutMs": 30000,
      "toolTimeoutMs": 240000,
        "enabledTools": [
          "dftk_doctor",
          "dftk_search_capabilities",
          "dftk_suggest",
          "dftk_describe",
          "dftk_run",
          "dftk_case",
          "dftk_read_case_run"
        ]
    }
  }
}
```

Install the Skill with either:

```bash
dftk skill --install --target kimi
```

or the generic shared target:

```bash
dftk skill --install --target agents
```

Start a new Kimi session after changing MCP configuration.

## TRAE

TRAE supports stdio MCP. In TRAE Settings → MCP, add a custom server using the same command/arguments:

```json
{
  "mcpServers": {
    "dftk": {
      "command": "dftk",
      "args": ["mcp", "--root", "/absolute/path/to/case"]
    }
  }
}
```

For the Skill, import/copy the complete `DFTK-skill` directory according to TRAE's Agent Skills UI/workspace mechanism. Do not reduce it to a single `SKILL.md`, because the skill uses progressive `references/`.

## WorkBuddy / CodeBuddy

WorkBuddy/CodeBuddy supports stdio MCP with `type`, `command`, and `args`:

```json
{
  "mcpServers": {
    "dftk": {
      "type": "stdio",
      "command": "dftk",
      "args": ["mcp", "--root", "/absolute/path/to/case"]
    }
  }
}
```

Skill install targets:

```bash
dftk skill --install --target workbuddy,codebuddy
```

## Other Agent hosts

Any MCP client able to launch a local stdio process can use:

```text
command: dftk
args: [mcp, --root, <authorized evidence root>]
```

Any AgentSkills-compatible host can use the complete standalone `DFTK-skill` directory or the generic `~/.agents/skills/dftk/` install target.

## Security note

DFTK MCP constrains **DFTK MCP calls**. It cannot prevent a host Agent from using some unrelated unrestricted shell/filesystem tool. For forensic evidence handling, configure the host Agent's own permissions so DFTK is the intended evidence-access path and do not grant broader write/shell access than the examination requires.

## Capability suggestions

`dftk suggest capture.pcap` and MCP `dftk_suggest(query="capture.pcap")`
rank candidates using known filenames, extensions, bounded file-header probes,
and the live registry. MCP relative paths resolve under the server's evidence root;
outside paths and symlink escapes are rejected before probing. Missing files can
still be planned from their names. Only regular files are probed (at most 4096 bytes).

Use `direction="produce"` with a required output kind such as `tls_sni`,
`timeline`, or `partition_table`. This mode matches declared `produces` values
and never reads files. It does not enumerate downstream steps from an input file.

Each candidate includes `why`, all `reasons`, its parameter contract, dependencies,
and `policy_allowed` / `policy_blockers`. Policy eligibility checks safety and
network access only; it does not establish format validity or dependency availability.
Suggestions are discovery hints, not findings. Confirm the contract with
`dftk_describe`, then evaluate the actual run's status and evidence. A successful
lookup with no matches is not a negative forensic finding.

CLI `--max-safety` and `--allow-network` only annotate the proposed policy in
suggestions; this command never executes a capability or changes server policy.
