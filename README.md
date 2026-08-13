# DFTK — Digital Forensics Toolkit

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/dftk.svg)](https://pypi.org/project/dftk/)

DFTK is a capability layer for digital forensics. It exposes read-only, structured forensic operations you can call from the CLI or compose inside a higher-level Agent / TaskGraph runtime. Every operation returns one `Observation` that carries an explicit status, machine-readable facts, and evidence traced back to its source.

> 🇨🇳 中文文档：[README.zh-CN.md](README.zh-CN.md)

- **Distribution name:** `dftk` · **Import package:** `dftk` · **CLI command:** `dftk`
- **Maintainer:** [DyNooob](https://github.com/DyNooob) — DigiForensics
- **Organizations:** [DigiForensics](https://www.digiforensics.cn) · [LLMCN](https://www.llmcn.org)
- **License:** [Apache-2.0](LICENSE)

---

## What DFTK is (and isn't)

DFTK is not an autonomous forensic agent. It is a library of stable, structured operations; you drive it, it does not investigate on its own. Each operation returns a normalized `Observation` so the calling system gets facts and sourced evidence instead of console text to parse.

## Why DFTK

- **Read-only by default.** Nothing touches source evidence unless you explicitly raise the safety ceiling.
- **Zero mandatory dependencies.** The base package installs anywhere with no third-party runtime requirements. Optional parsers (E01/TSK, Windows Registry/EVTX, DKIM/SPF, SSH) report `unsupported` when their dependency is missing, instead of guessing.
- **One registry, 68 tools.** Each tool declares its parameters, safety level, semantic tags, network needs, and produced-evidence types, so a planner can pick the right tool from an evidence requirement.
- **Safety enforced in one place.** `READ_ONLY < STATEFUL < DESTRUCTIVE`; no registered tool is `DESTRUCTIVE`. Network access is gated behind an explicit opt-in.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Native MCP for Agents](#native-mcp-for-agents)
- [Agent Skill](#agent-skill)
- [Python / Agent API](#python--agent-api)
- [Observation contract](#observation-contract)
- [Capability model](#capability-model)
- [Safety model](#safety-model)
- [Supported Python versions](#supported-python-versions)
- [Development](#development)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Disclaimer](#disclaimer)

## Installation

```bash
pip install dftk
```

Optional integrations install as extras:

```bash
pip install "dftk[email]"     # DKIM / SPF / DNS email authentication
pip install "dftk[ssh]"       # fixed-command read-only SSH inventory
pip install "dftk[windows]"   # Windows Registry / EVTX parsers
pip install "dftk[all]"       # every optional parser
```

The base package keeps **zero mandatory runtime dependencies** on purpose. E01 filesystem traversal additionally needs a forensic environment that provides `pyewf` / libewf bindings and `pytsk3`.

## Quick start

List every registered capability:

```bash
dftk list
```

Inspect a tool's contract (parameters, safety level, tags, produced evidence):

```bash
dftk describe android.apk_manifest
```

Analyze an artifact:

```bash
dftk run artifact.inspect --params '{"path":"sample.apk"}'
```

Extract Android manifest evidence:

```bash
dftk run android.apk_manifest --params '{"path":"sample.apk"}'
```

Search an APK for network endpoints:

```bash
dftk run android.apk_endpoints --params '{"path":"sample.apk"}'
```

Extract protocol-level observations from a capture:

```bash
dftk run network.capture_protocols --params '{"path":"traffic.pcapng"}'
```

Search a SQLite database without opening it read/write:

```bash
dftk run database.sqlite_search --params '{"path":"app.db","query":"example"}'
```

Run a bounded first-pass recipe:

```bash
dftk recipe artifact.auto_triage --params '{"path":"unknown.bin"}'
```

Export the full tool manifest (agent-readable):

```bash
dftk export-manifest --out manifest.json
```

Check the current runtime and optional integrations:

```bash
dftk doctor
```

Build an investigation case and correlate its runs into one timeline:

```bash
dftk case new --name intake
dftk case run <case_id> timeline.file_metadata --params '{"root":"mnt/evidence"}'
dftk case timeline <case_id>
```

### Native MCP for Agents

DFTK 3.1 adds a native local **stdio MCP** adapter. It is a thin protocol layer over the existing Registry / Observation / CaseSession APIs, not a second Agent runtime.

Install the optional MCP dependency and start the server from the evidence root you intend to expose:

```bash
pip install "dftk[mcp]"
cd /path/to/authorized/evidence-root
dftk doctor
dftk mcp
```

The MCP server exposes six meta-tools: health check, capability search, describe, run, case management, and paged reading of persisted case runs. It defaults to `READ_ONLY`, network-off, stdio-only operation. The Agent cannot raise the safety ceiling or enable network access; `--root`, `--max-safety`, `--allow-network`, and timeout are set by whoever launches the server.

For multi-step investigations, create a normal DFTK case and pass its `case_id` to the MCP `dftk_run` tool; the Observation is persisted in the same `CaseSession` format the CLI uses.

### Agent Skill

The standalone investigation guidance lives at `DigiForensics/DFTK-skill`. DFTK 3.1 bundles the matching release snapshot and installs the **entire** progressive-disclosure skill directory (not only `SKILL.md`):

```bash
dftk skill --install
dftk skill --install --target kimi,workbuddy,agents
```

The skill stays documentation and reasoning guidance; the executable capabilities remain in DFTK.

## Python / Agent API

```python
import dftk

registry = dftk.get_registry()

observation = dftk.run_tool(
    "artifact.inspect",
    {"path": "evidence.bin"},
)

print(observation.status)   # ok | partial | error | unsupported | blocked
print(observation.facts)    # machine-readable findings
print(observation.evidence) # source + locator + value + confidence
```

`get_registry()` and `run_tool()` are the stable public integration entry points. Callers do not need to import primitive modules for registration side effects.

## Observation contract

Every tool returns one structured `Observation` with distinct execution states:

```text
status       ok | partial | error | unsupported | blocked
facts        machine-readable findings
evidence[]   source + locator + value + confidence / method / source hash
warnings[]   limitations that do not erase useful evidence
errors[]     execution or parsing failures
meta         tool and run metadata
```

`unsupported`, `error`, `blocked`, and a genuine negative finding are deliberately **different** states. A missing parser is not the same as "no findings".

## Capability model

DFTK 3.1.0 contains a registry of **68 tools** (67 `READ_ONLY`, 1 `STATEFUL`) and **14 recipes** spanning:

- artifact identification, hashing, strings, search and timeline;
- APK, DEX, binary AXML, Android app data and endpoint extraction;
- ELF and PE inventory plus native indicators;
- SQLite and SQL dump analysis;
- PCAP / PCAPNG, DNS, HTTP and TLS SNI extraction;
- Linux root filesystems, authentication and persistence artifacts;
- Docker metadata and logs;
- web configuration and access logs;
- Windows Registry, USB artifacts and EVTX through optional parsers;
- E01 / TSK filesystem inventory through specialist forensic bindings;
- Chromium / Edge and Firefox artifacts;
- MIME / email authentication analysis;
- BIP39, entropy and reversible encoding helpers;
- unified timeline correlation and investigation case sessions: merge event sources into one source-attributed timeline, and accumulate tool runs in an isolated `dftk case` workspace.

### Case correlation & unified timeline

`timeline.merge` normalizes and correlates time-bearing events from multiple dftk tool outputs (or inline sources) into one sorted, source-attributed timeline. It is useful for fusing filesystem metadata, authentication logs and browser history.

`dftk case` wraps the read-only tools into an isolated investigation session. It records each run's `Observation` under a workspace (`.dftk/cases/<id>/`) and can correlate them into a single timeline or export a report:

```bash
dftk case new --name phishing-intake
dftk case run <case_id> timeline.file_metadata --params '{"root":"mnt/phone"}'
dftk case run <case_id> linux.auth_events      --params '{"root":"mnt/server"}'
dftk case timeline <case_id>     # unified, source-attributed timeline
dftk case export <case_id> --format md
```

See [`CAPABILITIES.md`](CAPABILITIES.md) for the detailed map.

## Safety model

DFTK separates execution safety from forensic reasoning:

| Level | Behavior |
|-------|----------|
| `READ_ONLY` | reads evidence or immutable / read-only views |
| `STATEFUL` | may write derived workspace output without changing source evidence |
| `DESTRUCTIVE` | reserved for target-modifying actions; **not registered** in 3.1.0 |

The default policy allows only `READ_ONLY` operations. Network access is independently gated and must be enabled with `--allow-network`. Controlled archive extraction (`archive.extract_safe`) is `STATEFUL` and blocked unless the caller explicitly raises the ceiling:

```bash
dftk run archive.extract_safe \
  --max-safety STATEFUL \
  --params '{"path":"evidence.zip","output_dir":"workspace/extracted"}'
```

Full details on database access, archive guards, specialist-parser semantics and the legacy-script policy are in [`SAFETY.md`](SAFETY.md).

## Supported Python versions

DFTK supports **CPython 3.10+** on platform-independent builds. Verified on 3.10, 3.11, 3.12 and 3.13.

## Development

```bash
git clone https://github.com/DigiForensics/DFTK.git
cd DFTK
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

Build distributions (for maintainers):

```bash
python -m build
python -m twine check --strict dist/*
```

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — public tool boundary, evidence contract, primitive-vs-recipe, promotion rules.
- [`CAPABILITIES.md`](CAPABILITIES.md) — full capability map by domain.
- [`SAFETY.md`](SAFETY.md) — safety levels, network isolation, database/archive guards, specialist-parser semantics.
- [`AGENT_INTEGRATION.md`](AGENT_INTEGRATION.md) — native stdio MCP and host-Agent integration examples.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to add a capability and open a PR.
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure policy.
- [`CHANGELOG.md`](CHANGELOG.md) — notable public changes.
- [`PUBLISHING.md`](PUBLISHING.md) — release / PyPI Trusted Publishing workflow.

## Contributing

Small, deterministic forensic primitives are preferred over challenge-specific answer scripts. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full guidelines, then open a pull request.

## Security

Report vulnerabilities privately — do **not** open a public issue. See [`SECURITY.md`](SECURITY.md).

## License

Released under the [Apache License 2.0](LICENSE). Copyright 2026 DyNooob @ DigiForensics.

## Disclaimer

DFTK is a technical toolkit, not legal advice. It is built to support lawful, authorized examination of evidence you own or are explicitly permitted to analyze. You are responsible for complying with applicable laws, authorization requirements, and chain-of-custody practices in your jurisdiction. The maintainers accept no liability for misuse.
