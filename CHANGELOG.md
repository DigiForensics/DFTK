# Changelog

All notable public changes to DFTK are recorded here.

## 3.3.0 — Chain-of-custody audit ledger & robustness (2026-08-16)

New:

- Added an append-only chain-of-custody audit ledger (`dftk.core.audit.ToolAuditLog`). Every capability run can append one JSONL record carrying timestamp, tool, caller, resolved parameters (secret-looking keys masked, oversized strings truncated), safety level, network flag, status, summary, evidence SHA-256 hashes and errors. Enable it per invocation with `--audit PATH` on `dftk run`, `dftk recipe`, `dftk case run` and `dftk mcp`, or process-wide via the `DFTK_AUDIT_LOG` environment variable. The ledger is a side record: it never modifies evidence, and ledger serialization or I/O failures are swallowed so an examination is never interrupted by logging problems.
- Added a test-coverage gate. `pyproject.toml` now carries a `test` extra and `[tool.coverage]` configuration, and CI runs the suite under `--cov-fail-under=60` (current measured coverage is ~70%).
- Added a schema-driven no-crash regression test that invokes every registered capability with well-formed parameters derived from its own JSON schema and asserts the runner always returns an `Observation` instead of letting an exception escape.

Fixed:

- `file.strings` and `file.strings_unicode` no longer read the whole input into memory with `read_bytes()`; they now go through the bounded reader (4 GB default ceiling) and report `unsupported` on oversized input instead of risking exhaustion on multi-gigabyte evidence.
- MCP parameter validation no longer misclassifies opaque text as a filesystem path. Previously any string containing `/` or `\` was path-checked, which wrongly rejected values such as Windows registry keys (`HKLM\...`) and search patterns containing separators. Validation now applies to declared path parameters, explicit `./` / `../` relative paths, absolute paths, and values that actually resolve inside the evidence root.
- `CaseSession` run-sequence allocation is now serialized by an in-process lock in addition to the advisory file lock. The file lock covers cross-process callers (CLI plus MCP); the thread lock guarantees same-process thread serialization regardless of filesystem lock behaviour, resolving intermittent sequence races observed under load.
- `windows.*` FILETIME values are converted with integer arithmetic instead of float division, removing sub-microsecond drift on large 100-nanosecond values.
- `dftk prepare --rewrite-from` no longer rewrites arbitrary text files inside the toolkit. It now touches only launcher scripts (`.bat`/`.cmd`/`.ps1`) and backs up every file it changes under the DFTK-managed shim dir first, so the rewrite is reversible and never mangles data/config. Passing the toolkit's own location as `--rewrite-from` is now a no-op.
- `dftk mcp` no longer hardpins `mcp==2.0.0`; it accepts the validated 2.x line (`>=2.0.0,<3`) so a 2.0.1 SDK release does not break startup. The version string in the rejection message now reflects the actual DFTK release instead of a stale `3.1.0`.
- `dftk skill --install` no longer copies VCS/CI metadata (`.git`, `.gitignore`, `.github`) into the installed Agent skill directory.
- `archive.inventory` streams the archive central directory and stops after `limit` members instead of materializing the entire directory up front, so peak memory stays proportional to `limit` on very large archives (ZIP and TAR).
- The tool runner now distinguishes caller parameter errors from internal tool bugs: a `TypeError` raised while *binding* the call is reported as `Invalid parameters`, while a `TypeError` raised inside a tool body surfaces as `Tool execution failed` rather than being misreported as a caller mistake.
- The MCP server (`dftk mcp`) previously returned top-level `ok: true` for **every** capability run regardless of the underlying `observation.status`, so a client that branched on `ok` could mistake an `unsupported`/`error` run for success. The server now derives the top-level `ok` from `observation.status` (`ok` / `partial` → `true`; `unsupported` / `error` / `blocked` → `false`), and the gateway distinguishes a genuine worker crash (marked `error_type`) from a semantic failure (which carries a real `Observation` with `status` and `errors`). Client guidance was updated accordingly in the Skill.

## 3.2.1 — External tool discovery on POSIX

- Fixed external-tool discovery on POSIX hosts: launcher scripts (`.bat`/`.cmd`/`.ps1`) shipped in the toolkit bundle are now treated as runnable by presence alone instead of requiring the POSIX execute bit. `dftk prepare` plus `detect_external_tools` / `dftk doctor` now correctly locate these tools off-PATH on Linux/macOS CI hosts. Native binaries (`.exe`) and extensionless scripts still require the execute bit.

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
