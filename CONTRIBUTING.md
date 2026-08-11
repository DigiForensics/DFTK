# Contributing

DFTK favors small, deterministic forensic primitives over challenge-specific answer scripts.

A new capability should:

1. accept generic artifact parameters rather than embedding case constants;
2. preserve source evidence by default;
3. distinguish `unsupported`, `error`, `blocked`, and negative findings;
4. return structured facts and explicit evidence locators;
5. declare safety level, network behavior, optional requirements, tags and produced evidence types;
6. include regression tests for both successful parsing and malformed/unsupported input;
7. avoid silently swallowing parser errors.

Development setup:

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

Before opening a release PR:

```bash
python -m build
python -m twine check --strict dist/*
```
