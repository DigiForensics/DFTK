# DFTK 3.6.1

A focused reliability release on top of 3.6.0: **128 capabilities across 28
domains**, with 124 READ_ONLY tools, four STATEFUL workspace operations, 113
primitives and 15 recipes. The companion Skill adds coverage and recovery
guidance and refreshes its capability catalog.

## Sequence hunting

`timeline.hunt_sequences` searches ordered event chains across persisted DFTK
Observation JSON files and inline event bundles. A rule declares a unique `id`,
two to eight ordered `steps`, one to eight `group_by` fields, and a positive
`within_seconds` window of up to seven days. An optional `severity` is an
analyst-supplied label, not a computed risk score.

The tool reuses `timeline.merge` normalization, so results carry the same
source attribution and locators as a merged timeline. It modifies no source
evidence and adds no runtime dependency. It is reachable from the CLI, Python,
Case runs, and the MCP registry adapter.

```bash
dftk run timeline.hunt_sequences \
  --params-file examples/sequences/download-execute-connect.json
```

The shipped example correlates one download → execution → connection lead for
the same host and account inside 120 seconds. These event kinds are illustrative
rather than a universal mapping of every parser's native records; inspect your
own `facts.events` fields and write selectors for them. The tool correlates
recorded events. It does not acquire missing artifacts or infer events that were
never parsed.

## Case coverage gate

`dftk_case(action="coverage")` reports execution limitations, pending analysis,
run statuses, and artifact integrity before a negative finding, final report, or
handoff. `next` can return `action="review"` for a failed or partial prior run so
a retry targets the specific dependency or input gap instead of looping blindly.

`no_recorded_limitations` describes recorded execution history. It does not
prove full acquisition, and it does not prove that no relevant activity exists.
A missing or corrupted result is a gap; a digest mismatch requires reviewing the
persisted result and every conclusion derived from it.

## Correctness and tooling

- Percent-encode SQLite file URIs so evidence paths containing `?`, `#`, `%`,
  spaces, and Unicode open the intended file in immutable mode.
- Add Agent host detection and harden the MCP worker guard.
- Resolve external readiness through toolchain discovery rather than assuming a
  missing optional engine is absent.
- Add end-to-end demos covering SQLite/WAL recovery, raw disk image plus MBR
  extraction, Windows MFT/UsnJrnl/Amcache, PCAP → HTTP → PE triage, and
  memory-image degradation. Each runs under an explicit SafetyPolicy that
  separates a read-only evidence root from a writable workspace, records every
  call in the audit ledger, and verifies the rendered report with `case.verify`.
  Demo runtime output is no longer tracked in the repository.

## Installation

```bash
pip install --upgrade dftk
pip install --upgrade "dftk[mcp]"  # optional local MCP interface
dftk doctor
dftk selftest
dftk skill --install               # matching v3.6.1 companion bundle
```

Keep acquired evidence and writable case material separate:

```bash
dftk mcp --root /evidence --workspace /cases/intake --check
```

## Scope of validation

The suite reports 532 passed, 4 skipped. Skips are optional native engines that
are absent from the test environment, and they remain explicitly unsupported at
runtime rather than silently approximated. Documentation counts and version
claims are asserted against the live registry, so the advertised 128/124/4
split cannot drift from the code.

This release does not claim that every parser was exercised against real
acquisition formats, nor that every optional third-party engine is installed.
Structural metadata and code-signature presence are not cryptographic trust or
behavioral verdicts.
