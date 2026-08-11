# DFTK — Digital Forensics Toolkit

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/badge/PyPI-dftk%20%C2%B7%20soon-lightgrey.svg)](#installation)

**Evidence-preserving forensic primitives and composable workflows for analysts, automation systems, and autonomous agents.**

> 🇨🇳 中文文档：[README.zh-CN.md](README.zh-CN.md)

- **Distribution name:** `dftk` · **Import package:** `dftk` · **CLI command:** `dftk`
- **Maintainer:** [DyNooob](https://github.com/DyNooob) — DigiForensics
- **Organizations:** [DigiForensics](https://www.digiforensics.cn) · [LLMCN](https://www.llmcn.org)
- **License:** [Apache-2.0](LICENSE)

---

DFTK is a **capability layer**, not an autonomous forensic agent. It exposes stable, structured forensic operations that can be driven directly from the CLI or composed by a higher-level Agent / TaskGraph runtime. Every operation returns a normalized `Observation` with explicit status, machine-readable facts, and source-traceable evidence — so upstream systems can reason about findings instead of scraping terminal output.

## Why DFTK

- **Evidence-first.** Reads are read-only by default; nothing mutates source evidence unless you explicitly raise the safety ceiling.
- **Zero mandatory dependencies.** The base package installs cleanly anywhere with no third-party runtime requirements. Specialist parsers (E01/TSK, Windows Registry/EVTX, DKIM/SPF, SSH) are optional extras and report `unsupported` when absent rather than silently guessing.
- **Agent-ready.** A single registry of 66 tools with JSON contracts, semantic tags, declared safety level, network gating, and produced-evidence types — designed for planners to select tools from an evidence requirement.
- **Safe by construction.** `READ_ONLY < STATEFUL < DESTRUCTIVE`; no registered tool is `DESTRUCTIVE`. Network traffic is independently gated behind an explicit opt-in.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
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

Optional integrations are installed as extras:

```bash
pip install "dftk[email]"     # DKIM / SPF / DNS email authentication
pip install "dftk[ssh]"       # fixed-command read-only SSH inventory
pip install "dftk[windows]"   # Windows Registry / EVTX parsers
pip install "dftk[all]"       # every optional parser
```

The base package intentionally keeps **zero mandatory runtime dependencies**. E01 filesystem traversal additionally requires a forensic environment providing `pyewf` / libewf bindings and `pytsk3`.

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

`unsupported`, `error`, `blocked`, and a genuine negative finding are deliberately **different** states — a missing parser is not the same as "no findings".

## Capability model

DFTK 2.1.0 contains a registry of **66 tools** (65 `READ_ONLY`, 1 `STATEFUL`) and **13 recipes** spanning:

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
- BIP39, entropy and reversible encoding helpers.

See [`CAPABILITIES.md`](CAPABILITIES.md) for the detailed map.

## Safety model

DFTK separates execution safety from forensic reasoning:

| Level | Behavior |
|-------|----------|
| `READ_ONLY` | reads evidence or immutable / read-only views |
| `STATEFUL` | may write derived workspace output without changing source evidence |
| `DESTRUCTIVE` | reserved for target-modifying actions; **not registered** in 2.1.0 |

The default policy allows only `READ_ONLY` operations. Network access is independently gated and must be enabled with `--allow-network`. Controlled archive extraction (`archive.extract_safe`) is `STATEFUL` and blocked unless the caller explicitly raises the ceiling:

```bash
dftk run archive.extract_safe \
  --max-safety STATEFUL \
  --params '{"path":"evidence.zip","output_dir":"workspace/extracted"}'
```

Full details — database access, archive guards, specialist-parser semantics, legacy-script policy — are in [`SAFETY.md`](SAFETY.md).

## Supported Python versions

DFTK supports **CPython 3.10+** on OS-independent platforms. Verified on 3.10, 3.11, 3.12 and 3.13.

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
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to add a capability and open a PR.
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure policy.
- [`CHANGELOG.md`](CHANGELOG.md) — notable public changes.
- [`PUBLISHING.md`](PUBLISHING.md) — release / PyPI Trusted Publishing workflow.

## Contributing

Small, deterministic forensic primitives are favored over challenge-specific answer scripts. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full guidelines, then open a pull request.

## Security

Please report vulnerabilities privately — do **not** open a public issue. See [`SECURITY.md`](SECURITY.md).

## License

Released under the [Apache License 2.0](LICENSE). Copyright 2026 DyNooob @ DigiForensics.

## Disclaimer

DFTK is a technical toolkit, not legal advice. It is designed to support lawful, authorized forensic examination of evidence you own or are explicitly permitted to analyze. Users are responsible for compliance with applicable laws, authorization requirements, and chain-of-custody practices in their jurisdiction. The maintainers accept no liability for misuse.
