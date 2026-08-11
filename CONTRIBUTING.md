# Contributing to DFTK

> 🇨🇳 中文简述：我们更倾向于小而确定的取证原语，而非针对特定题目的答案脚本。新增能力请遵循下方原则，并附带回归测试；发布前请用 `python -m build` 与 `python -m twine check --strict` 校验分发包。

DFTK favors small, deterministic forensic primitives over challenge-specific answer scripts.

## Principles for a new capability

A new capability should:

1. accept generic artifact parameters rather than embedding case constants;
2. preserve source evidence by default;
3. distinguish `unsupported`, `error`, `blocked`, and negative findings;
4. return structured facts and explicit evidence locators;
5. declare safety level, network behavior, optional requirements, tags and produced evidence types;
6. include regression tests for both successful parsing and malformed / unsupported input;
7. avoid silently swallowing parser errors.

## Development setup

```bash
git clone https://github.com/DigiForensics/DFTK.git
cd DFTK
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

## Adding a tool

1. Implement the primitive in `src/dftk/primitives/` (or a recipe in `src/dftk/recipes/`).
2. Register it with the `ToolRegistry` decorator, declaring `name`, `description`, `parameters`, `safety`, `network`, `tags`, `produces`, `requires`, `deterministic`, and `cost_hint`.
3. Return a single `Observation` with explicit `status`, `facts`, and `evidence`.
4. Add regression tests under `tests/`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the public tool boundary, evidence contract, and promotion rules.

## Before opening a release PR

```bash
pytest -q
python -m build
python -m twine check --strict dist/*
```

## Pull request expectations

- Keep changes focused and described in the PR body.
- Add or update tests for behavioral changes.
- Update `CHANGELOG.md` for user-visible changes.
- Follow the existing code style (4-space indentation, `from __future__ import annotations`).
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Reporting security issues

Do **not** open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).
