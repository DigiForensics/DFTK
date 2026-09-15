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

### Verifying the audit ledger

Every record written by this version carries `seq`, `prev_hash` and `record_hash`:
each record hashes its own content and links to the previous one, so the ledger can
prove it has not been edited.

```bash
dftk audit verify /cases/phishing-intake/ledger.jsonl          # 0 intact, 1 defective, 2 unreadable
dftk audit verify /cases/phishing-intake/ledger.jsonl --seal ledger.seal.json
dftk audit seal /cases/phishing-intake/ledger.jsonl            # external anchor for the tail
```

`verify` recomputes the whole chain and reports, per record, whether it was edited,
deleted, reordered, truncated or downgraded to an unchained format. It is read-only
and never writes to the ledger.

Deleting records from the *end* of a ledger leaves the remaining chain internally
consistent, so the file cannot prove its own tail on its own. `dftk audit seal`
writes an external anchor (record count, last record hash, whole-file SHA-256);
store it with the case report and pass it back with `--seal`. A defective ledger
refuses to seal.

The same check is available as the `custody.ledger_verify` capability, which returns
`facts.verdict` (`intact`/`legacy`/`partial`/`defective`) and cites the ledger as
`Evidence`. A negative integrity finding is an examination result, not a tool
failure: the status stays `ok` and the defects appear in `warnings`.

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
