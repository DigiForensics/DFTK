# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in DFTK, please report it privately to
the maintainers. We will acknowledge receipt and work with you on a
coordinated disclosure.

- **Security contact:** i@digiforensics.cn
- **Subject line:** `DFTK security vulnerability — <short summary>`

Include as much of the following as possible:

- a description of the vulnerability and its impact;
- steps to reproduce or a proof of concept;
- affected versions (e.g. `3.2.1`);
- any suggested mitigation, if known.

You can expect an initial acknowledgement within a few business days. Once the
issue is confirmed, we will agree on a disclosure timeline that balances user
safety with responsible publication.

## Supported versions

Only the latest published release line receives security fixes.

| Version | Supported |
|---------|-----------|
| 3.2.x   | ✅ Yes |
| < 3.2   | ❌ No |

## Scope notes

DFTK is a **read-only, evidence-preserving** toolkit by design:

- no registered tool is `DESTRUCTIVE`;
- network access is gated behind `--allow-network`;
- SQLite access is read-only (`mode=ro&immutable=1`, `query_only=ON`);
- archive extraction is `STATEFUL` and rejects path-traversal / oversized members.

Reports about deviations from this model (e.g. a tool that unexpectedly writes
to or modifies source evidence, or performs network traffic without the
explicit opt-in) are in scope and prioritized.

For the full safety model, see [SAFETY.md](SAFETY.md).
