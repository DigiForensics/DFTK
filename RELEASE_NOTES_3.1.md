# DFTK 3.1.0 release notes

DFTK 3.1 keeps the project boundary introduced in 3.0: DFTK is a deterministic forensic capability layer, not an autonomous Agent. The release adds a native Agent transport and strengthens the existing case workspace without changing the public Observation/Evidence contract.

## Native MCP

`pip install "dftk[mcp]"` adds the MCP Python SDK version validated by this release. `dftk mcp` runs a local stdio server that exposes only six meta-tools around the existing DFTK abstractions:

- health/doctor;
- capability search;
- capability describe;
- capability run;
- CaseSession management;
- paged reading of a persisted case run.

The model cannot pass network/safety escalation parameters. The server owner selects the evidence root, safety ceiling (READ_ONLY or STATEFUL), network opt-in, workspace, and hard timeout at launch. DFTK primitive execution occurs in an isolated child process so third-party parser output cannot corrupt MCP stdio framing.

## CaseSession hardening

Case manifests and run Observation files now use atomic replacement. Per-case advisory locking serializes the manifest read/sequence/write transaction across threads and processes. `show()` and `read_run()` expose the existing persisted case data to other DFTK interfaces without inventing a second state store. Case IDs and persisted artifact paths are constrained to their case directory.

## Agent Skill bundle

The matching `DFTK-skill` 3.1.0 release is a progressive-disclosure directory rather than a single-file usage note. DFTK embeds a release snapshot and `dftk skill --install` copies the entire bundle, including references, examples and templates.

The standalone `DigiForensics/DFTK-skill` repository remains the authoring/source repository for investigation guidance; DFTK carries the version-matched release snapshot for convenient installation.

## Compatibility

- Base DFTK still has zero mandatory third-party dependencies.
- Existing CLI commands and public `get_registry()` / `run_tool()` integration remain available.
- Existing `Observation`, `Evidence`, tool names, recipes and 3.0 case manifest schema are preserved.
- Native MCP is optional and stdio-only in 3.1.0 by design.
