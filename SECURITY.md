# Security policy

## Report a vulnerability

Report security vulnerabilities privately to **i@digiforensics.cn**, with subject
`DFTK security vulnerability — <summary>`. Avoid public issues containing an
unfixed exploit, real evidence, credentials or personal data.

Include the affected version/commit, operating system, Python/optional dependency
versions, minimal synthetic reproduction, expected/observed behavior and impact.
Useful targets include source mutation, path escapes, undeclared network access,
secret disclosure, unsafe extraction and parser resource exhaustion. Coordinate
disclosure with the maintainer; no fixed response-time guarantee is offered here.

## Supported versions

Security fixes target the latest maintained release line. The current source line
is **3.7.x**. Older releases are not promised security backports; use the current
release/upgrade guidance rather than treating historical release notes as policy.

## Intended boundary

The runtime has READ_ONLY and derived-workspace STATEFUL capabilities; none is
DESTRUCTIVE. MCP applies declared path roles, safety/network gates and worker
deadlines. Scoped visual consent and CPU-OCR consent are separate host attestations.

DFTK is not an OS sandbox, universal media decoder, malware execution environment
or credential vault. A read-only source mount and appropriate host permissions
remain important. External binaries, model weights, Python packages and MCP hosts
have their own trust boundaries. For the detailed contract see [SAFETY.md](SAFETY.md).
