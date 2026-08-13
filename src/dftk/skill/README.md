# DFTK Skill

The standalone Agent Skill for [DigiForensics/DFTK](https://github.com/DigiForensics/DFTK).

DFTK provides deterministic forensic capabilities and structured Observation/Evidence output. This repository teaches an Agent how to turn a forensic question into evidence requirements, choose the right DFTK capabilities, verify the findings, and write conclusions that trace back to source.

## Version

`3.1.0` — for DFTK `3.1.x`.

## Install

Install the **whole `dftk/` skill directory**, not just `SKILL.md`. The skill loads `references/` on demand, so omitting that folder breaks the guidance.

Common user-level locations:

```text
~/.agents/skills/dftk/
~/.kimi-code/skills/dftk/
~/.workbuddy/skills/dftk/
~/.claude/skills/dftk/
~/.codex/skills/dftk/
~/.hermes/skills/dftk/
```

Or install the bundled release snapshot from DFTK 3.1:

```bash
dftk skill --install
```

## Structure

```text
dftk/
  SKILL.md            # entry point: when to use DFTK, how to scope a case
  references/         # domain playbooks, loaded progressively
  examples/           # worked investigation snippets
  templates/          # output report templates
```

## Design boundary

This repository contains no forensic parser and no Agent runtime. It holds Agent instructions, references, examples, and templates. The executable capabilities live in the `DFTK` repository / PyPI package.
