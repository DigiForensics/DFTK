# DFTK — Digital Forensics Toolkit

[![CI](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml/badge.svg)](https://github.com/DigiForensics/DFTK/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dftk.svg)](https://pypi.org/project/dftk/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

DFTK gives an investigation Agent evidence access, perception, bounded actions
and source-linked memory. The Agent decides what to examine, connects the evidence
and evaluates conclusions. Analysts can use the same capabilities through the CLI
or Python API.

**Current source version: 3.7.0 · 136 capabilities · 29 domains · 8 MCP meta-tools.**
The registry contains 121 primitives and 15 recipes: 131 READ_ONLY, five STATEFUL,
and no DESTRUCTIVE tools. [中文说明](README.zh-CN.md)

## What it can do

| Need | DFTK supplies |
|---|---|
| Find evidence | Paged directory browsing, signatures, hashes, text windows and literal/regex search; intake retains media and inaccessible-content hints |
| Examine images and video | Metadata/EXIF, consent-gated native images, numbered contact sheets, source-coordinate crops and timestamped video samples |
| Read image text | Local single/batch OCR, CUDA/MPS first, raw text/boxes/confidence and source hashes; CPU only after affirmative consent |
| Reach nested evidence | ZIP/TAR inventory and workspace extraction; one-candidate OpenSSL decryption; registered derived files can feed later tools in the same Case |
| Parse artifacts | SQLite/WAL/recovery, Android, browser, Windows/Linux, PCAP/PCAPNG, email, binary and filesystem evidence; selected external-engine adapters |
| Retain and verify work | Persisted Observations, paged results, artifact dispositions, interrupted attempts, timelines, entity correlation, findings and audit verification |

See the [capability map](CAPABILITIES.md) for supported operations and limits.
Recipes and next-action suggestions are optional helpers; they do not define a
mandatory investigation sequence.

## Connect an Agent

Python 3.10+ is required. Install the runtime in a persistent environment:

```bash
python -m pip install --upgrade "dftk[mcp]"
dftk agent setup \
  --root /evidence/acquisition \
  --workspace /cases/investigation \
  --install-skill \
  --config-out /cases/investigation/dftk-agent-config.json
```

The evidence directory must already exist. Keep it read-only and put the writable
workspace outside it. Setup installs the complete, version-matched
[DFTK-skill bundle](https://github.com/DigiForensics/DFTK-skill), binds the active
Python interpreter, enables a workspace audit ledger and emits JSON/TOML MCP
fragments. Import the appropriate fragment in your host and start a new session.
Setup does not edit the host's global MCP configuration.

Choose `--target <host>` if detection is uncertain; `--dry-run` previews the plan.
Check the server before connecting:

```bash
dftk mcp --root /evidence/acquisition --workspace /cases/investigation --check
```

MCP defaults to READ_ONLY, network off and a 180-second worker timeout. Extraction,
decryption, HTTP body export and HTML reporting require a launch policy allowing
STATEFUL operations. See [installation](INSTALL_AGENT.md),
[Agent integration](AGENT_INTEGRATION.md) and [MCP configuration](docs/mcp.md).

## Images, video and OCR

For image previews/contact sheets install `dftk[media]` alongside MCP; for local
OCR install `dftk[ocr]`. Provision GPU-compatible PyTorch and trusted EasyOCR weights
separately; set `DFTK_OCR_MODEL_DIR` to the model directory. Video metadata/sampling
also needs FFmpeg/FFprobe on PATH. Examination calls never download OCR weights.

Pixels reach the host model only when it supports images and the user has granted
consent for the file/scope. Otherwise report the discovered media without pixels.
Local OCR is separate from model vision. GPU failure never silently authorises
slow CPU OCR; explain the cost and obtain affirmative consent before `allow_cpu=true`.

Video support is sampled frames, with at most eight frames per request; audio and
unsampled content remain unexamined. Thumbnails, crops and empty OCR output do not
establish full-content review. [Perception contracts](docs/media-perception.md)

## CLI and Python

The core package has no mandatory third-party runtime dependencies:

```bash
python -m pip install dftk
dftk suggest /evidence/acquisition/History
dftk search "图片文字识别"
dftk describe database.sqlite_query
dftk run artifact.inspect --params '{"path":"/evidence/acquisition/sample.bin"}'
dftk case --workspace /cases/investigation new --name investigation
dftk case --workspace /cases/investigation run CASE_ID artifact.inspect --params '{"path":"/evidence/acquisition/sample.bin"}'
dftk case --workspace /cases/investigation coverage CASE_ID
```

Replace `CASE_ID` with the ID returned by `case new`. These JSON examples use a
POSIX shell; use `--params-file` for portable or sensitive parameter input.
Direct CLI calls do not inherit an MCP server's roots or process timeout.

```python
import dftk

result = dftk.run_tool("artifact.inspect", {"path": "/evidence/sample.bin"})
print(result.to_dict())
```

Every capability returns an Observation with status, facts, evidence and limits.
`partial` requires review; `unsupported`, `blocked` and `error` are not evidence
that the sought activity is absent. [User guide](docs/user-guide.md)

## Optional integrations

| Extra | Purpose |
|---|---|
| `mcp` | Local stdio MCP server; SDK `>=2.0.0,<3` |
| `media` / `ocr` | Pillow previews / EasyOCR and its dependencies |
| `windows` | Optional Registry/EVTX parsers; several host-artifact readers are native |
| `image` / `ese` | EWF/TSK bindings / SRUM ESE reader; native libraries or build prerequisites may be needed |
| `email` / `ssh` / `yara` | DKIM/SPF/DNS / fixed SSH collection / YARA scanning |
| `all` | All optional Python groups, including OCR and native bindings; external binaries and weights are separate |

`dftk doctor` reports readiness and installation gaps. Discovering an external tool
does not create an adapter for all of its commands. [Toolchain setup](DEPLOY-TOOLCHAIN.md)

## Documentation and boundaries

- [User guide](docs/user-guide.md): discovery, cases, results, Python and audit.
- [Capability map](CAPABILITIES.md) and [static manifest](docs/capabilities.json).
- [Architecture](ARCHITECTURE.md), [safety](SAFETY.md) and [security reporting](SECURITY.md).
- [Sequence hunting](docs/sequence-hunting.md) and [reliability validation](docs/agent-reliability.md).
- [Development](docs/development.md), [documentation maintenance](docs/documentation.md) and [publishing](PUBLISHING.md).
- [3.7.0 release notes](RELEASE_NOTES_3.7.md) and [changelog](CHANGELOG.md).

DFTK does not guarantee complete acquisition or real-case evidence recall. Some
encrypted ZIP methods and RAR/7z extraction remain unsupported. OpenSSL decryption
requires a supplied candidate and explicit parameters; it does not guess or impose
a global retry budget on the host Agent. MCP path checks constrain DFTK calls,
not unrelated tools available to the host. Preserve raw sources and review coverage.

Distribution/import/CLI: `dftk`. Maintainer: [DyNooob](https://github.com/DyNooob)
at [DigiForensics](https://www.digiforensics.cn). License: [Apache-2.0](LICENSE).
