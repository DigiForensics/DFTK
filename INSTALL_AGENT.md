# Install DFTK from an Agent

Give an Agent this repository URL:

```text
https://github.com/DigiForensics/DFTK
```

DFTK is the primary entry point. The Agent installs the DFTK runtime first; the
runtime then fetches and installs the matching `DFTK-skill` release automatically.
The user should not need to provide the DFTK-skill URL separately.

From a checked-out repository, an Agent performs:

```text
python -m pip install --upgrade ".[mcp]"
dftk agent setup --root <read-only-evidence-dir> --workspace <writable-case-dir> --install-skill
```

For a published package, replace the first line with:

```text
python -m pip install --upgrade "dftk[mcp]"
```

`dftk agent setup` resolves the DFTK-skill release matching the installed DFTK
version, installs the complete bundle (root Skill, references, templates, and
specialist skills), and produces a reviewable MCP configuration fragment. It detects
a single current host when possible and otherwise safely falls back to the portable
`agents` directory. Add `--dry-run` to inspect its plan, or pass `--target codex`
(or another explicit target) when required.

Keep `--root` read-only and use a separate writable `--workspace` for Case and
audit material. See [AGENT_INTEGRATION.md](AGENT_INTEGRATION.md) for MCP host
configuration.
