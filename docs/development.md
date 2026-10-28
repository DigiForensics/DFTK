# Development guide

Use Python 3.10+; CI covers 3.10, 3.11, 3.12 and 3.13. The base runtime has no
mandatory third-party dependencies. Development installs MCP, Pillow and testing/
packaging tools, but not every optional forensic engine or OCR model.

## Environment and checks

```bash
git clone https://github.com/DigiForensics/DFTK.git
cd DFTK
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q --cov=dftk --cov-report=term-missing --cov-fail-under=60
.venv/bin/python scripts/check_docs.py
```

On Windows substitute `.venv\Scripts\python.exe`. Explicit environment paths avoid
installing dependencies into a different interpreter. Optional tests may skip
when engines/binaries are absent; inspect skip reasons rather than treating them
as validation of those integrations. `credibility` adds differential-test oracles.
Real GPU OCR also requires the `ocr` extra, a compatible GPU runtime and local weights.

## Add or change a capability

Implement a bounded primitive under `src/dftk/primitives/`, or a small composition
under `recipes/`; add its module to the built-in loader when needed. Declare the
full parameter schema, safety, network behavior, path roles, dependencies, tags,
outputs and cost. Parameters should bind the Python function signature.

Return one Observation. Preserve raw values, source/record locators, explicit
limits, and useful partial results. State missing dependencies/unsupported formats
rather than silently pretending a weaker method is equivalent. Registered
workspace outputs need source-linked DerivedArtifacts with concrete paths/hashes.

Tests should verify meaningful parsing/results, bounds, malformed inputs and
source preservation. Exercise parent-policy inheritance for recipes and actual
native MCP content when changing transport. Avoid tests that only repeat prose
or implementation constants. No mock GPU test proves real CUDA/MPS behavior.

## Keep contracts and guides synchronized

```bash
.venv/bin/python -m dftk export-manifest --out docs/capabilities.json --force
.venv/bin/python scripts/check_docs.py
```

The committed manifest is static; `--runtime-readiness` is for local diagnostics,
not this file. With the companion repository checked out alongside:

```bash
.venv/bin/python ../DFTK-skill/scripts/sync_capabilities.py --import-manifest docs/capabilities.json --write
.venv/bin/python ../DFTK-skill/scripts/check_docs.py
```

Update the capability map, affected examples and paired READMEs. Specialist Skill
descriptions also feed its generated catalog. Do not manually edit generated files
or rewrite historical releases as if they described current behavior.
[Documentation ownership](documentation.md)

## Package validation

```bash
.venv/bin/python -m build
.venv/bin/python -m twine check --strict dist/*
```

Install the resulting wheel in a separate environment and run from outside the
checkout. Confirm version, registry loading, optional-dependency behavior and the
MCP/Skill bootstrap paths affected by the change. Building from source and testing
an editable checkout are different checks. See [publishing](../PUBLISHING.md).
