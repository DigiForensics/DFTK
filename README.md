# DFTK

**Digital Forensics Toolkit** — evidence-preserving forensic primitives and composable workflows for analysts, automation systems, and autonomous agents.

Maintained by **DyNooob** under **DigiForensics**, with **LLMCN**.

- DigiForensics: https://www.digiforensics.cn
- LLMCN: https://www.llmcn.org

DFTK is a capability layer, not an autonomous forensic agent. It exposes stable, structured forensic operations that can be used directly from the CLI or composed by a higher-level Agent/TaskGraph runtime.

## Install

```bash
pip install dftk
```

Optional integrations:

```bash
pip install "dftk[email]"
pip install "dftk[ssh]"
pip install "dftk[windows]"
pip install "dftk[all]"
```

The base package intentionally keeps zero mandatory runtime dependencies. Specialist parsers return `unsupported` when their optional dependency is unavailable instead of silently falling back to weaker guesses.

E01 filesystem traversal additionally requires a forensic environment providing `pyewf`/libewf bindings and `pytsk3`.

## Quick start

List capabilities:

```bash
dftk list
```

Inspect a tool contract:

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

## Python / Agent API

```python
import dftk

registry = dftk.get_registry()

observation = dftk.run_tool(
    "artifact.inspect",
    {"path": "evidence.bin"},
)

print(observation.status)
print(observation.facts)
print(observation.evidence)
```

`get_registry()` and `run_tool()` are the stable public integration entry points. Callers do not need to import primitive modules for registration side effects.

## Observation contract

Every tool returns one structured `Observation` with distinct execution states:

```text
status       ok | partial | error | unsupported | blocked
facts        machine-readable findings
evidence[]   source + locator + value + confidence/method/source hash
warnings[]   limitations that do not erase useful evidence
errors[]     execution or parsing failures
meta         tool and run metadata
```

`unsupported`, `error`, `blocked`, and a genuine negative finding are deliberately different states.

## Capability model

DFTK 2.1.0 contains a registry of reusable primitives and bounded recipes spanning:

- artifact identification, hashing, strings, search and timeline;
- APK, DEX, binary AXML, Android app data and endpoint extraction;
- ELF and PE inventory plus native indicators;
- SQLite and SQL dump analysis;
- PCAP/PCAPNG, DNS, HTTP and TLS SNI extraction;
- Linux root filesystems, authentication and persistence artifacts;
- Docker metadata and logs;
- web configuration and access logs;
- Windows Registry, USB artifacts and EVTX through optional parsers;
- E01/TSK filesystem inventory through specialist forensic bindings;
- Chromium/Edge and Firefox artifacts;
- MIME/email authentication analysis;
- BIP39, entropy and reversible encoding helpers.

See `CAPABILITIES.md` in the source distribution for the detailed map.

## Safety model

DFTK separates execution safety from forensic reasoning:

- `READ_ONLY` — reads evidence or immutable/read-only views;
- `STATEFUL` — may write derived workspace output without changing source evidence;
- `DESTRUCTIVE` — reserved for target-modifying actions and not registered in DFTK 2.1.0.

The default policy allows only `READ_ONLY` operations. Network access is independently gated.

For example, controlled archive extraction is blocked unless the caller explicitly raises the safety ceiling:

```bash
dftk run archive.extract_safe \
  --max-safety STATEFUL \
  --params '{"path":"evidence.zip","output_dir":"workspace/extracted"}'
```

Network tools require `--allow-network`.

## Development

```bash
git clone <your-repository-url>
cd DFTK
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

Build distributions:

```bash
python -m build
python -m twine check --strict dist/*
```

## Project identity

**DFTK — Digital Forensics Toolkit**  
Maintainer: **DyNooob**  
DigiForensics: https://www.digiforensics.cn  
LLMCN: https://www.llmcn.org

## License

A public license has intentionally not been selected in this release candidate. Select and add a `LICENSE` file before the production PyPI publish workflow is enabled.
