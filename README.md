# DFTK — Digital Forensics Toolkit

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/dftk.svg)](https://pypi.org/project/dftk/)

DFTK is a Python toolkit for evidence-preserving digital-forensics operations. It
provides structured results for files, archives, mobile artifacts, databases,
captures, browser data, email, host artifacts, and timelines.

中文说明见 [README.zh-CN.md](README.zh-CN.md).

## Install

```bash
pip install dftk
```

Optional integrations:

```bash
pip install "dftk[email]"    # DKIM / SPF / DNS
pip install "dftk[ssh]"      # read-only SSH inventory
pip install "dftk[windows]"  # Registry / EVTX parsers
pip install "dftk[yara]"     # YARA rule scanning
pip install "dftk[mcp]"      # local MCP server
pip install "dftk[all]"      # all optional Python integrations
```

The core package has no mandatory third-party runtime dependencies. E01 filesystem
traversal additionally requires `pyewf` / libewf bindings and `pytsk3`.

## Start here

```bash
# Discover available capabilities
dftk list

# Build an Agent-ready intake manifest and next-step plan
dftk run evidence.intake --params '{"path":"/evidence/acquisition"}'

# Inspect one capability before running it
dftk describe artifact.inspect

# Analyze an artifact
dftk run artifact.inspect --params '{"path":"sample.apk"}'

# Save related observations in a case
dftk case --workspace /cases/intake new --name intake
dftk case --workspace /cases/intake run <case_id> artifact.inspect --params '{"path":"sample.apk"}'
dftk case --workspace /cases/intake export <case_id> --format md
```

Each run returns an `Observation` with a status, facts, evidence, warnings, and
errors. `unsupported`, `error`, and `blocked` describe limitations or failures;
they are not negative findings.

## Agent and MCP use

For Agent use, the recommended entry point is this **DFTK repository**: give its
URL to the Agent. It installs DFTK first, then runs a single bounded bootstrap that
fetches the matching complete [DFTK-skill](https://github.com/DigiForensics/DFTK-skill)
bundle and emits a reviewable MCP configuration fragment:

```bash
dftk agent setup --root /evidence/acquisition --workspace /cases/intake --install-skill
```

See [INSTALL_AGENT.md](INSTALL_AGENT.md) for the paste-ready instruction and
[AGENT_INTEGRATION.md](AGENT_INTEGRATION.md) for the complete operating loop.

DFTK includes a local stdio MCP server. Keep acquired evidence read-only and use a
separate writable case workspace:

```bash
pip install "dftk[mcp]"
dftk mcp --root /evidence/acquisition --workspace /cases/intake --check
dftk mcp --root /evidence/acquisition --workspace /cases/intake
```

The server defaults to `READ_ONLY` with network access disabled. Its launch options
define the evidence root, safety ceiling, network access, and timeout. See the
[MCP guide](docs/mcp.md) for configuration and policy details.

For an existing host configuration, install the matching Skill bundle directly:

```bash
dftk skill --install  # auto-detect the current Agent host; portable fallback: agents
# Inspect all supported target paths before a broad installation:
dftk skill --install --target all --dry-run
```

## Documentation

- [User guide](docs/user-guide.md) — CLI, Python API, cases, observations, and audit logs.
- [MCP guide](docs/mcp.md) — local server policy and host configuration.
- [Capability map](CAPABILITIES.md) — domains and capability groups.
- [Architecture](ARCHITECTURE.md) — registry, evidence contract, and runtime boundaries.
- [Safety policy](SAFETY.md) — execution levels, network gates, and source-evidence protection.
- [Toolchain deployment](DEPLOY-TOOLCHAIN.md) — external forensic binaries.
- [Development guide](docs/development.md) — setup, tests, and contribution workflow.
- [Documentation policy](docs/documentation.md) — ownership, generated data, and translation rules.

## Project facts

- Distribution: `dftk`; Python package: `dftk`; CLI: `dftk`.
- Python: CPython 3.10+.
- License: [Apache-2.0](LICENSE).
- Maintainer: [DyNooob](https://github.com/DyNooob) · [DigiForensics](https://www.digiforensics.cn).

DFTK supports lawful, authorized examination of evidence. It is a technical toolkit,
not legal advice.
