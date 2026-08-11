# Digital Forensics Toolkit 2.1 — release notes

2.1 expands the generalized toolkit without reintroducing competition-specific answer scripts. The unit of reuse remains a bounded forensic primitive that returns a structured `Observation` and explicit evidence.

## Release snapshot

- **66 registered capabilities**
- **13 recipes**
- **65 READ_ONLY**, **1 STATEFUL**, **0 DESTRUCTIVE**
- **3 network-gated** capabilities
- **42 regression tests passing**
- **25 / 25** generalized Python modules AST-parse successfully
- **0 bare `except:`** in `src/dftk`
- **0 known legacy case constants** in registered source

## New capability families

- artifact identification, tree inventory/search and filesystem timeline;
- safe policy-gated archive extraction;
- Android AXML Manifest, APK signing markers, endpoint extraction and app-data inventory;
- PE metadata and bounded native indicator scans;
- PCAPNG plus DNS, HTTP and best-effort TLS SNI extraction;
- immutable SQLite query/search and generic SQL dump inventory;
- Linux auth, persistence/history, Docker logs and web log/config analysis;
- optional Windows Registry/USB/EVTX parsers;
- optional E01/TSK filesystem inventory;
- Chromium/Edge/Firefox history/download/cookie metadata;
- email MIME/attachment hashing;
- entropy profiling and reversible encoding candidates.

## Agent/runtime integration

Tool contracts now expose `tags`, `produces`, `requires`, `deterministic`, `cost_hint`, safety class and network policy. Manifest schema is version 2. Agents can select capabilities by evidence product rather than guessing from tool names.

Stable public Python entry points were added:

- `dftk.get_registry()`
- `dftk.run_tool()`

## Intentional limitations

2.1 does not pretend to be a complete parser for every forensic format. Specialist capabilities use real parser dependencies and return `UNSUPPORTED` when those dependencies are absent. Current high-value gaps include TCP stream reassembly, full PCAPNG timestamp-option handling, deep recursive E01 extraction, Windows Prefetch/LNK/SRUM, browser-secret decryption and the full Android resources stack.
