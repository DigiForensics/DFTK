---
name: dftk
description: Evidence-preserving digital forensics (DFIR) toolkit for agents. 66 read-only/stateful tools across Android, Linux, Windows, network, email, and crypto, behind a safety-gated Observation/Evidence contract. Use when an agent must collect, hash, parse, or analyze forensic artifacts without mutating evidence.
version: 2.1.0
author: DyNooob @ DigiForensics
license: Apache-2.0
tags:
  - forensics
  - dfir
  - incident-response
  - security
  - evidence
---

# dftk — Digital Forensics Toolkit (Agent Skill)

dftk is a **capability layer**, not an autonomous forensic agent: a set of
evidence-preserving primitives and composable recipes for analysts, automation,
and agents. Every tool returns a structured `Observation` (status + facts +
evidence with source provenance).

This folder is the **standalone skill**. It is distributed independently of the
Python package so it can be published/copied on its own (like any other agent
skill). The dftk *code* it wraps lives on PyPI.

## Install

The skill is a single `SKILL.md` that every major agent loads the same way
(folder per skill, `SKILL.md` inside), so one file serves them all. Make it
available to an agent by any of:

1. **Standalone (skill only, no pip needed for the skill itself):** copy this
   folder into the agent's skills directory. Known locations:
   - WorkBuddy: `~/.workbuddy/skills/dftk/`
   - Claude Code: `~/.claude/skills/dftk/`
   - OpenAI Codex: `~/.codex/skills/dftk/`
   - Hermes: `~/.hermes/skills/dftk/`
   - Agent Skills open standard (Codex, Cursor, Gemini CLI, GitHub Copilot, 70+):
     `~/.agents/skills/dftk/`
2. **Via the dftk library (registers everywhere at once):** `pip install dftk`,
   then:
   - `dftk skill --install` → copies `SKILL.md` into **all** known agent dirs
     above in one go.
   - `dftk skill --install --target claude,codex,hermes` → only the agents you
     name (options: `workbuddy,claude,codex,hermes,agents,cursor,gemini`, or
     `all`).
   - `dftk skill --install --dir /path/to/skills/dftk` → a custom directory.

Either way, the dftk **code** must be installed for the tools to actually run:
`pip install dftk` (optionally `pip install "dftk[all]"` for the expert
parsers). If `dftk` is not on PATH, an agent can run it on the fly with
`uvx dftk ...`.

## How to invoke

Two modes; prefer the CLI for isolation.

### A. CLI (recommended for agents)
- `dftk list [--tag TAG]` — list tools
- `dftk list --produces <evidence-type>` — find tools by the evidence type they produce
- `dftk describe <tool>` — show the parameter JSON schema
- `dftk run <tool> --params '{"path":"..."}'` — execute
- `dftk export-manifest` — dump the full tool catalog as JSON (hand this to a planner)
- Network-accessing tools require `--allow-network`; anything above READ_ONLY
  requires `--max-safety STATEFUL`.

### B. In-process Python
```python
from dftk import get_registry, run_tool
obs = run_tool("file.hash", {"path": "README.md"})
print(obs.status, obs.facts, obs.evidence)
```
Optional extras: `pip install "dftk[windows]"` (registry/EVTX), `[email]`
(DKIM/SPF), `[ssh]` (SSH forensics), `[all]`. Missing deps make the relevant
tools return `unsupported` rather than guess.

## Safety model (must respect)
- **Read-only by default.** Only `--max-safety STATEFUL` permits STATEFUL
  tools. dftk registers **no DESTRUCTIVE** tools.
- **Network off by default**; must be enabled with `--allow-network`. Outbound
  tools are blocked otherwise.
- Every tool returns a structured `Observation`: `status`
  (ok/partial/unsupported/error), `facts` (extracted data), `evidence` (with
  `source` provenance). Treat `evidence.source` as part of the chain of
  custody — never interpret facts divorced from their source.
- Never mutates source evidence. Anything that would alter the target is out
  of scope.

## Guidance for planners
1. Call `dftk export-manifest` first to get the live catalog (name, description,
   safety, tags, produces, parameters).
2. Select tools by the evidence type they `produce` or by `tags`, not by
   guessing names.
3. Before running, `dftk describe <tool>` to confirm parameters; pass them as
   `--params` JSON.
4. Handle returns: `unsupported` ⇒ missing dependency (suggest the matching
   extra); `error` ⇒ read the message in `facts`.

## Coverage (categories, not exhaustive)
file, archive, hash, timeline, android, linux, windows (registry, evtx),
network, email (dkim, spf), crypto, database, ssh — 66 tools + 13 recipes.

## Copyright
Copyright 2026 DyNooob @ DigiForensics. Released under the Apache License 2.0.
