# Development guide

## Setup

```bash
git clone https://github.com/DigiForensics/DFTK.git
cd DFTK
python -m venv .venv
python -m pip install -e ".[dev]"
pytest -q
```

Run the CI coverage gate locally:

```bash
pytest -q --cov=dftk --cov-report=term-missing --cov-fail-under=60
```

## Adding a capability

1. Add a bounded operation under `src/dftk/primitives/`.
2. Register a `ToolSpec` with parameters, evidence types, safety, network needs, and
   optional requirements.
3. Return a structured `Observation`; do not rely on terminal output as an API.
4. Add focused tests, including error and dependency behavior.
5. Update the generated capability material and affected examples.

See [CONTRIBUTING.md](../CONTRIBUTING.md), [ARCHITECTURE.md](../ARCHITECTURE.md), and
[documentation.md](documentation.md).
