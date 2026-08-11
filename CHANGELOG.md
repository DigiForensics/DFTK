# Changelog

All notable public changes to DFTK are recorded here.

## 2.1.0 — Public release candidate

- Renamed the PyPI distribution from `digital-forensics-toolkit` to `dftk`.
- Kept the Python import package and CLI command as `dftk`.
- Added stable public Python entry points: `dftk.get_registry()` and `dftk.run_tool()`.
- Expanded the registered capability layer to artifact, Android, binary, database, network, Linux/server, Docker/web, Windows, E01, browser, email and crypto domains.
- Added explicit safety levels and separate network gating.
- Added agent-readable tool metadata including tags, produced evidence types, optional requirements, determinism and cost hints.
- Added PyPI/GitHub release automation scaffolding using Trusted Publishing.

The detailed technical changes from the internal 2.0/2.1 development cycle remain documented in `RELEASE_NOTES_2.1.md`.
