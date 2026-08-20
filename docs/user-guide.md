# User guide

## Choose an interface

Use the CLI for local automation and scripting, Python for application integration,
and MCP when an MCP host should enforce evidence-root and execution policy.

```bash
dftk list
dftk search "browser downloads"
dftk describe android.apk_manifest
dftk run android.apk_manifest --params '{"path":"sample.apk"}'
```

Inspect a capability before running it. Its description lists accepted parameters,
safety level, network requirement, optional dependencies, and result types.

## Read results

Every operation returns an `Observation`:

| Field | Meaning |
|---|---|
| `status` | `ok`, `partial`, `unsupported`, `error`, or `blocked` |
| `facts` | machine-readable findings |
| `evidence` | source-linked observations |
| `warnings` | coverage or interpretation limits |
| `errors` | execution or parsing errors |

Treat `unsupported`, `error`, and `blocked` as distinct from a negative finding.

For CLI automation, `ok` and `partial` return exit code 0, `error` returns 1, and
`unsupported` or `blocked` return 2.

## Cases and audit records

Use a case for related runs. Keep the workspace separate from the acquired
evidence directory; the default is `$DFTK_WORKSPACE` or `~/.dftk`.

```bash
dftk case --workspace /cases/phishing-intake new --name phishing-intake
dftk case --workspace /cases/phishing-intake run <case_id> artifact.inspect --params '{"path":"mail.eml"}'
dftk case --workspace /cases/phishing-intake timeline <case_id>
dftk case --workspace /cases/phishing-intake export <case_id> --format md
```

Use `--audit PATH` or `DFTK_AUDIT_LOG` to append execution metadata to a JSONL log.
The audit log is case material and does not replace the evidence included in an
`Observation`.

When `--out` is used, DFTK refuses to replace an existing file unless `--force` is
also passed. Choose an output path outside the evidence root.

## Python API

```python
import dftk

observation = dftk.run_tool("artifact.inspect", {"path": "evidence.bin"})
print(observation.status)
print(observation.evidence)
```

`dftk.get_registry()` and `dftk.run_tool()` are the public integration points.
