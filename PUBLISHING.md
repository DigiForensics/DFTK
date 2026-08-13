# Publishing DFTK

The public distribution name is `dftk`.

```bash
pip install dftk
```

The import package and CLI command are also both `dftk`.

## One-time setup

1. Create the public GitHub repository that will own the release workflow.
2. Add the repository identity to `pyproject.toml` under `[project.urls]` once the URL is final.
3. Select a public license and add it as `LICENSE`.
4. On PyPI, configure a **pending Trusted Publisher** for the `dftk` project using the GitHub owner, repository name, workflow file `publish.yml`, and environment `pypi`.
5. Optionally configure the equivalent pending publisher on TestPyPI for workflow file `testpypi.yml` and environment `testpypi`.
6. In the GitHub repository, create environments named `pypi` and `testpypi`. Protect the production `pypi` environment if desired.

No long-lived PyPI API token is required when Trusted Publishing is used.

## Local release validation

```bash
python -m pip install -U build twine
rm -rf dist build
python -m build
python -m twine check --strict dist/*
```

Then create a clean virtual environment and install the generated wheel:

```bash
python -m venv clean-env
# Windows: clean-env\\Scripts\\activate
# POSIX:   source clean-env/bin/activate
pip install dist/dftk-3.1.0-py3-none-any.whl
dftk --version
dftk list
```

## TestPyPI

The included `testpypi.yml` workflow is manual (`workflow_dispatch`). Configure the TestPyPI pending Trusted Publisher first, then run the workflow from GitHub Actions.

## Production PyPI

The included `publish.yml` workflow publishes only for version tags matching `v*` and refuses to publish if a `LICENSE` file is absent.

Typical release:

```bash
git tag v3.1.0
git push origin v3.1.0
```

The workflow runs tests, builds both wheel and sdist, validates metadata, then publishes using GitHub OIDC / PyPI Trusted Publishing.

PyPI distributions are immutable per filename/version. If a release is wrong after upload, fix it and publish a new version instead of trying to overwrite 3.1.0.
