# Install DFTK for an Agent

Use the [DFTK repository](https://github.com/DigiForensics/DFTK) as the installation
entry point. DFTK installs its matching companion Skill; a separate Skill URL is
not required. This guide describes the current 3.7.0 source workflow.

## Prepare the runtime

Use Python 3.10+ in a persistent virtual environment. For a published version:

```bash
python -m venv /opt/dftk-env
/opt/dftk-env/bin/python -m pip install --upgrade "dftk[mcp]"
```

Replace `/opt/dftk-env` with a writable location. On Windows use
`C:\path\dftk-env\Scripts\python.exe` instead of `bin/python`. From a local
checkout, install `".[mcp]"` with that interpreter. The installed version selects
the companion tag: 3.7.0 uses `v3.7.0`; it does not fetch the newest Skill branch.

For images add `media`; for OCR add `ocr`, provision GPU support and weights as
described in [media perception](docs/media-perception.md). `all` is optional and
can require large downloads or native-library builds.

## Prepare one host

Choose an existing evidence directory and a separate writable workspace:

```bash
/opt/dftk-env/bin/python -m dftk agent setup \
  --root /evidence/acquisition --workspace /cases/investigation \
  --target agents --install-skill \
  --config-out /cases/investigation/dftk-agent-config.json
```

`agents` selects the portable `~/.agents/skills` location. Replace it with the
actual host when known: `workbuddy`, `codebuddy`, `kimi`, `claude`, `codex`,
`hermes`, `cursor` or `gemini`. Without an explicit target, setup detects one host
from environment markers and falls back to `agents`. Codex installation respects
`CODEX_HOME`. Do not select every host unless the user requested that scope.

Add `--dry-run` to preview destinations and policy without creating files,
installing Skills or launching the server. Setup refuses an existing config file
unless `--force` is supplied. It installs the main Skill, the progressive resource
tree and 31 standalone specialist Skills; it does not install their external tools.

## Connect and verify

The output contains `mcp_json` and `codex_toml`. Import the relevant fragment using
the host's normal configuration mechanism, approve the local server as required
by that host, and start a new session. Global host configuration is not edited by
setup. Generated launch entries use the absolute installing Python executable
with `-m dftk` and enable `<workspace>/audit.jsonl`.

```bash
/opt/dftk-env/bin/python -m dftk mcp \
  --root /evidence/acquisition --workspace /cases/investigation --check
```

`--check` validates startup and may create the workspace; it does not run an
investigation. Keep the interpreter at the generated path. After moving/removing
the environment, regenerate the configuration. Restart a running MCP process and
refresh the Skill after upgrading; an existing process retains its loaded code.

The default policy is READ_ONLY, network off, timeout 180 seconds. When derived
workspace operations are authorised, pass `--max-safety STATEFUL` during setup.
Network opt-in is separate. Visual and CPU-OCR consent remain separate from both.

## Copyable Agent request

```text
Install DFTK from https://github.com/DigiForensics/DFTK for the current host.
Use a persistent Python environment, the evidence directory I specify and a
separate case workspace. Install the matching complete Skill, generate the MCP
fragment and verify it. Keep READ_ONLY/network-off defaults unless my task
authorises otherwise. Report any missing OCR weights or external dependencies.
```

For the operational contract see [Agent integration](AGENT_INTEGRATION.md) and
[MCP setup](docs/mcp.md).
