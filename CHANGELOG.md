# Changelog

All notable public changes to DFTK are recorded here.

## 3.2.0 — External toolchain preparation

- Added `dftk prepare <toolkit_root>` to fold the win-tool-launcher environment-preparation workflow into DFTK: it records the extracted forensic-toolkit root and a DFTK-managed shim directory in `~/.dftk/toolchain.json`, generates two-layer launchers (`.bat` for Windows terminals, extensionless wrapper for the agent Bash) plus `set_path.bat`/`set_path.sh`, and optionally rewrites hardcoded roots inside the bundle (`--rewrite-from`).
- Extended the external-binary resolver (`core/external_tools`) to also search a single unified `$DFTK_TOOLS` root and the `dftk prepare` config (under `<root>`, `<root>/bin`, `<root>/<name>`, `<root>/<category>`, and the shim dir). Tools are now found on subsequent `dftk` calls without any manual PATH edit, even when the toolkit is on a non-PATH / non-readable drive.
- `detect_external_tools` / `dftk doctor` now report a `source` field (`PATH` / `DFTK_*_TOOL_DIRS` / `DFTK_TOOLS / dftk prepare root` / `dftk prepare shims`) and `doctor_report` carries a `toolchain` section with the active `toolkit_root` / `bin_dir`.
- Added public helpers `resolve_external_tool(name)` and `external_tool_source(name)` for tool bodies that need to invoke a discovered binary.

## 3.1.1 — Native Windows host-artifact tools and pcap enrichment

- Added native, dependency-free Windows host-artifact tools: `windows.mft` (NTFS $MFT path rebuild, SI/FN timestamps, flags, size), `windows.prefetch` (.pf v17/23/26/30 executable, hash, run count, last run, referenced files), `windows.lnk` (target, timestamps, TrackerDataBlock machine/MAC), `windows.recyclebin` (Recycle Bin $I original name, size, deletion time, paired $R).
- Enriched `network.capture_protocols` with DNS answer records (A/AAAA, CNAME) and HTTP responses (status, reason, Server).
- Moved the DFTK Agent Skill out of the pip package; `dftk skill --install` now fetches the standalone `DFTK-skill` repository at the matching version tag and installs the main skill plus standalone analysis skills.
- Tool count is now 72 (was 68).

## 3.1.0 — Native MCP and complete Agent Skill bundle

- Added native local stdio MCP as a thin adapter over the existing ToolRegistry, Observation and CaseSession interfaces.
- MCP exposes six meta-tools for health, capability discovery, describe, execution, case management and paged case-run reading; it does not implement an autonomous Agent loop.
- MCP defaults to READ_ONLY, network-off operation; root scope, network opt-in and STATEFUL ceiling are server-owner launch settings and are not model tool arguments.
- Capability execution is isolated in a worker process with a hard timeout so noisy parser stdout cannot corrupt stdio MCP framing.
- Case-scoped MCP execution is serialized to protect the existing CaseSession manifest read/sequence/write operation from concurrent requests.
- Added `dftk doctor` environment/capability diagnostics.
- `dftk skill --install` now installs the full progressive-disclosure DFTK Skill bundle (references/examples/templates), with Kimi/CodeBuddy targets added alongside existing targets.
- Added optional `mcp` dependency extra; base DFTK continues to have zero mandatory runtime dependencies.
- Public Python integration remains `get_registry()` / `run_tool()` with no breaking Observation/Evidence changes.

## 3.0.0 — Unified timeline & case correlation

- Added unified timeline correlation: `timeline.merge` normalizes and merges time-bearing events from multiple dftk tool outputs or inline sources into one source-attributed, sorted timeline.
- Added investigation case sessions via the `dftk case` CLI (and `dftk.core.case` API): `new`, `list`, `run`, `timeline`, and `export` (JSON/Markdown). A case accumulates read-only tool runs in an isolated `.dftk/cases/<id>/` workspace and correlates them into a single timeline without ever mutating evidence.
- Added `recipe.timeline.unified` composing a filesystem metadata timeline with optional extra Observation sources.
- Added Apache-2.0 copyright headers to all source and test files.
- Registry now exposes 68 tools (67 READ_ONLY, 1 STATEFUL) and 14 recipes.
- No breaking changes to the existing Observation/Evidence contract or the public Python API (`get_registry`, `run_tool`).

## 2.1.0 — Public release candidate

- Renamed the PyPI distribution from `digital-forensics-toolkit` to `dftk`.
- Kept the Python import package and CLI command as `dftk`.
- Added stable public Python entry points: `dftk.get_registry()` and `dftk.run_tool()`.
- Expanded the registered capability layer to artifact, Android, binary, database, network, Linux/server, Docker/web, Windows, E01, browser, email and crypto domains.
- Added explicit safety levels and separate network gating.
- Added agent-readable tool metadata including tags, produced evidence types, optional requirements, determinism and cost hints.
- Added PyPI/GitHub release automation scaffolding using Trusted Publishing.

The detailed technical changes from the internal 2.0/2.1 development cycle remain documented in `RELEASE_NOTES_2.1.md`.
