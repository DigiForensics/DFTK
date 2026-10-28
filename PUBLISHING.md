# Publishing DFTK and its companion Skill

The distribution, import package and CLI are named `dftk`. Runtime and Skill
releases must have the same version tag. A push to main runs CI; it does not
publish to PyPI. Production publication is triggered by a new runtime `v*` tag.

## Prepare an unused version

Choose a new version that is absent from both release tags and PyPI. Existing
tags and PyPI files are not a mechanism for updating an already released package.
Documentation-only main commits do not change an existing wheel or PyPI README.

Synchronize `pyproject.toml`, runtime `__version__`, the static capability manifest,
current capability map and release notes. Synchronize Skill metadata, companion
manifest/catalog, specialist release metadata and current release notes. Preserve
historical changelog facts.

Use the development environment to run:

```bash
python scripts/check_docs.py
python -m pytest -q --cov=dftk --cov-report=term-missing --cov-fail-under=60
python -m build --outdir /tmp/dftk-release-dist
python -m twine check --strict /tmp/dftk-release-dist/*
```

Choose an empty output directory or a version-specific path so old distributions
do not enter validation/upload. On Windows use a suitable writable directory.
Install the exact wheel into a separate environment, run outside the checkout and
verify version, registry loading, the affected MCP paths and base/optional installs.
Run Skill documentation/catalog checks and a complete isolated bundle installation.

## Push the companion before the runtime tag

Commit/push both main branches and wait for the runtime Python 3.10–3.13 matrix
plus Skill documentation CI. Before publishing, push the matching Skill tag so
`dftk skill --install` can resolve it immediately after runtime installation.

The following are templates: replace `vX.Y.Z` with the selected unused version.

```bash
# In DFTK-skill, after validating the intended commit:
git tag -a vX.Y.Z -m "DFTK Skill X.Y.Z"
git push origin main refs/tags/vX.Y.Z

# In DFTK, after CI and companion verification:
git tag -a vX.Y.Z -m "DFTK X.Y.Z"
git push origin main refs/tags/vX.Y.Z
```

Verify a clean wheel can fetch/install the remote companion tag into an isolated
`--dir`; retain the main tree and all standalone specialists. Do not use a global
multi-host install to test a release.

## Production workflow

`.github/workflows/publish.yml` performs these stages on the runtime tag:

1. Install development requirements; check runtime/tag identity, the matching
   remote Skill tag, documentation, tests and the public LICENSE.
2. Build wheel/sdist, run strict Twine checks and upload the
   `python-package-distributions` Actions artifact.
3. Enter the `pypi` environment and publish with GitHub OIDC Trusted Publishing.

The PyPI project must trust the correct GitHub owner/repository, workflow
`publish.yml` and environment `pypi`. Long-lived upload tokens are not required.
If environment review is configured, build can succeed while publish is waiting;
the designated reviewer approves that concrete deployment in GitHub. Do not report
publication as complete until the publish job and package-index verification pass.

Monitor the exact commit/tag rather than an earlier failed run. Cross-version
failures must be fixed and CI rerun before selecting the release tag. Never move a
published tag to hide a fix; use a new version if a released artifact is wrong.

## TestPyPI and failure handling

`testpypi.yml` is manual (`workflow_dispatch`) and uses the `testpypi` environment
and its own Trusted Publisher. It is a separate index, not proof that production
published. Review its configured ref/version before running it.

For failed builds, inspect the first relevant error, fix the source and repeat
appropriate checks. For waiting deployment, review the environment gate rather
than rerunning tests. For upload conflicts, select a new version; filenames on
PyPI are immutable. Existing working code/Skill installs remain separate from
the state of the release pipeline.
