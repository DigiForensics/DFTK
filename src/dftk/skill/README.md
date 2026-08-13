# DFTK Skill

The standalone Agent Skill for [DigiForensics/DFTK](https://github.com/DigiForensics/DFTK).

DFTK provides deterministic forensic capabilities and structured Observation/Evidence output. This repository provides the investigation guidance that teaches an Agent how to turn a forensic claim into evidence requirements, select DFTK capabilities, verify findings, and report source-traceable conclusions.

## Version

`3.1.0` — intended for DFTK `3.1.x` (the core reasoning contract remains compatible with DFTK 3.0 CLI concepts; native MCP described by this release is introduced in DFTK 3.1).

## Install

Install the **whole `dftk/` skill directory**, not just `SKILL.md`; the main Skill loads `references/` progressively.

Common user-level locations include:

```text
~/.agents/skills/dftk/
~/.kimi-code/skills/dftk/
~/.workbuddy/skills/dftk/
~/.claude/skills/dftk/
~/.codex/skills/dftk/
~/.hermes/skills/dftk/
```

DFTK 3.1 can also install its bundled release snapshot:

```bash
dftk skill --install
```

## Design boundary

This repository contains no forensic parser and no autonomous Agent runtime. It contains only reusable Agent instructions, references, examples, and output templates. The executable capability layer lives in the `DFTK` repository / PyPI package.
