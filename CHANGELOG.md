# Changelog

All notable public changes to DFTK are recorded here.

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
