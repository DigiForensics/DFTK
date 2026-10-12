# DFTK 3.6.0

DFTK 3.6 combines the previously divergent development lines into one runtime:
**127 capabilities across 28 domains**, with 123 READ_ONLY tools, four STATEFUL
workspace operations, 112 primitives and 15 recipes. The companion Skill includes
31 updated specialist workflows and a generated catalog of the exact contracts.

The shared runtime now validates declared parameter types and bounds, advertises
host-path roles, resolves evidence and workspace inputs separately, and propagates
safety/network/root policy through recipe child calls. Bounded reads enforce the
actual read ceiling; directory traversal skips symlinks. Static manifests are
independent of installed optional parsers, with runtime readiness available on demand.

New analyst capabilities include explained discovery (`suggest` / `dftk_suggest`),
Chromium/Firefox bookmarks, Firefox cookie metadata, Chromium recorded search terms,
Mach-O/universal binary inventory, and streaming binary comparison. The integrated
runtime retains SQLite/FAT/REGF/E01 recovery, PE/ELF structure, network reassembly,
Windows host artifacts, memory adapters, YARA/web/EVTX hunts, guided intake, entity
correlation, HTML reports and case findings.

Audit and case verification now cover complete Observation content, derived hashes,
persisted artifact hashes and cited evidence-item content. Finding registration is
serialized across processes. Existing hash-chain records remain verifiable and can
be extended; seals continue to anchor an external checkpoint.

Compatibility fixes include Python 3.10/3.11 syntax, supported MCP SDKs, correct
pyesedb API use for SRUM, closed immutable SQLite handles and escaped file URIs.
YARA rule includes are disabled to prevent implicit out-of-scope file reads.

## Installation

```bash
pip install --upgrade dftk
pip install --upgrade "dftk[mcp]"  # optional local MCP interface
dftk doctor
dftk selftest
dftk skill --install               # matching v3.6.0 companion bundle
```

Keep acquired evidence and writable case material separate:

```bash
dftk mcp --root /evidence --workspace /cases/intake --check
```

## Scope of validation

Release checks cover the complete tool contract, parser regression fixtures,
read-only/path/network policy, malformed input, concurrency, audit/finding tampering,
package metadata, clean wheel installation, and the supported Python matrix.
Native optional engines absent from a test environment remain explicitly skipped or
unsupported. This does not claim every third-party engine or real acquisition
format has been exercised. Code-signature presence and structural metadata are not
cryptographic trust or behavioral verdicts.
