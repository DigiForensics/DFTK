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

<!-- Bundled copy for `dftk skill --install`. Canonical source of truth: skills/dftk/SKILL.md (standalone skill repo). Edit there and sync this file. -->

# dftk — Digital Forensics Toolkit (Agent Skill)

dftk is a **capability layer**, not an autonomous forensic agent: a set of
evidence-preserving primitives and composable recipes for analysts, automation,
and agents. Every tool returns a structured `Observation` (status + facts +
evidence with source provenance).

This folder is the **standalone skill**. It is distributed independently of the
Python package so it can be published/copied on its own (like any other agent
skill). The dftk *code* it wraps lives on PyPI.

## Install

Pick either way to make this skill available to an agent:

1. **Standalone (skill only, no pip needed for the skill itself):** copy this
   folder into your agent's skills directory, e.g.
   `~/.workbuddy/skills/dftk/`. (Or publish it to a skill marketplace as-is.)
2. **Via the dftk library:** `pip install dftk`, then
   `dftk skill --install` copies this same file into
   `~/.workbuddy/skills/dftk/`.

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
