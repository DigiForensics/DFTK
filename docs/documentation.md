# Documentation policy

## Ownership

| Content | Canonical location |
|---|---|
| Installation and first run | `README.md` |
| CLI, Python, cases, and audit usage | `docs/user-guide.md` |
| MCP policy and contract | `docs/mcp.md` |
| Runtime design and safety | `ARCHITECTURE.md`, `SAFETY.md` |
| Capability names and metadata | DFTK registry and `CAPABILITIES.md` |
| Investigation methodology | the separate `DFTK-skill` repository |

Keep entry pages short and link to the canonical document instead of copying sections.
Release notes describe changes only; they are not a second user guide.

## Generated capability data

The registry is the source of truth for capability names, parameters, safety, and
dependencies. `docs/capabilities.json` is the versioned generated manifest consumed
by integrations and the companion Skill repository. Regenerate it with:

```bash
dftk export-manifest --out docs/capabilities.json
```

Then run `python scripts/check_docs.py`. The check compares the generated manifest
and documented count with the loaded registry.

## Language policy

`README.md` and `README.zh-CN.md` are paired entry pages and should be updated in the
same change. Detailed documentation is English-first until a maintained translation
is added; a translated page must link to its canonical counterpart.
