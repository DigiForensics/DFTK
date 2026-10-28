# Documentation ownership and maintenance

Current guides describe the checked-in runtime contract. Package availability,
GitHub Actions state and PyPI approval are release-time facts; do not hardcode
transient pipeline status into a user guide.

| Content | Canonical location |
|---|---|
| Product scope and first steps | Paired `README.md` / `README.zh-CN.md` |
| Runtime/Skill installation | `INSTALL_AGENT.md` |
| Agent decisions and integration boundary | `AGENT_INTEGRATION.md` |
| CLI, Cases, Python and audit | `docs/user-guide.md` |
| MCP configuration, all eight tools, paging and paths | `docs/mcp.md` |
| Media consent, coordinates, OCR and video/decryption limits | `docs/media-perception.md` |
| Capability contracts | Registry; generated `docs/capabilities.json`; human capability map |
| Architecture/safety/security | `ARCHITECTURE.md`, `SAFETY.md`, `SECURITY.md` |
| External dependencies | `DEPLOY-TOOLCHAIN.md` |
| Tests and publishing | `docs/development.md`, `docs/agent-reliability.md`, `PUBLISHING.md` |
| Investigation methodology and specialist references | Separate DFTK-skill repository |

Keep the two README languages equivalent. Detailed runtime guides are English-first;
link rather than copying an entire secondary guide. Skill references must be
self-contained after installation while linking to runtime documentation for
installation details. Specialist guidance does not imply a matching parser exists.

## Generated data

Regenerate the static manifest from the registry and overwrite the tracked file
explicitly:

```bash
python -m dftk export-manifest --out docs/capabilities.json --force
python scripts/check_docs.py
```

Use the active development interpreter. Never commit runtime-specific readiness
from `--runtime-readiness` as the static contract. Synchronize the companion
manifest/catalog using its `scripts/sync_capabilities.py`; regenerate specialist
descriptions with its `scripts/generate_skill_catalog.py`.

## Review requirements

Validate command/parameter names against CLI help and registered contracts. Run
representative examples against synthetic evidence with a separate workspace.
Check local links, counts, safety classifications and referenced capability names.
For documentation-only edits, use these focused checks instead of inventing tests
that merely assert headings or duplicate prose.

Changelogs and versioned release notes are historical records; retain their
original version-specific counts. Label old development plans as historical where
they could be mistaken for current instructions. Update current capability limits,
deployment assumptions and examples rather than mechanically replacing every old
version string. Do not promise a security backport or an accuracy benchmark that
the project does not actually maintain.
