# Safety and evidence boundaries

DFTK preserves source evidence by design and defaults to offline READ_ONLY
capability execution. Keep acquired sources on an OS read-only mount where
appropriate; application path checks do not enforce a read-only mount themselves.

## Capability levels

The 3.7.0 registry contains 136 tools: 131 READ_ONLY, five STATEFUL and zero
DESTRUCTIVE. READ_ONLY classifies a capability's source-side effects; Case files,
audit records and runtime bookkeeping can still be written to the workspace.

| Level | Meaning |
|---|---|
| READ_ONLY | Evidence/metadata parsing, correlation, local perception or fixed remote collection; network and disclosure are separate controls |
| STATEFUL | Derived workspace outputs while preserving original sources |
| DESTRUCTIVE | Target/evidence mutation; no such capability is registered and MCP cannot select this ceiling |

The STATEFUL tools are `archive.extract_safe`, `crypto.openssl_decrypt`,
`filesystem.extract`, `network.http_sessions` and `case.report_html`. Destructive
scripts, arbitrary target-shell mutation and legacy challenge scripts are outside
the registry. CLI installation/toolchain setup are management commands with their
own writes; the capability level is not a global sandbox for the whole program.

## Roots and policy

MCP owns a source `--root` and separate writable `--workspace`. The workspace must
be outside source evidence by default. `--allow-workspace-in-root` is an explicit
compatibility exception and permits derived changes inside that tree.

Declared path roles distinguish source inputs, workspace outputs/inputs and
analysis material. Paths are resolved and containment-checked before execution.
Case-recorded derived files may be source inputs only at exact registered
workspace paths with matching digests. Directory metadata access does not grant
content access to every workspace file. Recipe children inherit parent policy.

Direct CLI/Python work does not inherit an MCP process's roots. Python callers
can supply `SafetyPolicy` roots; unscoped CLI callers must choose paths carefully.
MCP cannot constrain unrelated shell tools, malicious dependencies, every parser
exploit, or concurrent external changes to acquired files.

## Network, media and CPU are separate decisions

Network-declaring capabilities require `--allow-network`: `email.dkim_verify`,
`email.spf_verify`, `server.readonly_inventory` and `server.remote_snapshot`.
SSH uses fixed read-only collection profiles, not caller-supplied commands, and
rejects unknown host keys. Remote reads can still create access/audit effects.
This declaration gate is not an OS network sandbox; package installation, Skill
download, external-engine behavior and other host tools have separate controls.

Visual disclosure requires scoped user consent and confirmed model image support.
Both host attestations default false; without them, pixels are not decoded or
returned by the preview/contact-sheet operation. Discovery/metadata are not visual
review. Image pixels are transport-only and are not replayed from stored Case JSON.

Local OCR uses CUDA/MPS first, with provisioned weights and no examination-time
downloads. CPU execution requires affirmative consent; GPU failure is not consent.
DFTK rejects enabled implicit MPS CPU fallback for a GPU-only run. These controls
are attested by the host, not authenticated from chat by DFTK.
[Media contract](docs/media-perception.md)

## Containers and databases

ZIP/TAR extraction applies output containment, link/special-member, member-count
and expanded-size controls. Accessible ZIP members can be retained while others
need a password or decoder. Password inputs are supplied candidates, not guesses.
OpenSSL decryption accepts explicit parameters and only registers structurally
validated expected-format output. Structure checks do not authenticate origin,
prove correct attribution or prevent a host from making repetitive calls.

SQLite SQL readers use immutable/read-only main-database views. Query authorizers
reject writes; sidecars can contain excluded state. Forensic DB/WAL readers expose
bounded committed reconstruction and heuristic deleted candidates. Do not modify
the original database to make a parser accept it. Parser success or zero recovered
rows does not establish complete transaction/deletion history.

## Limits, persistence and audit

MCP worker deadlines bound process lifetime and protect protocol framing. Limits
inside parsers bound specific resources; a batch's cooperative budget is not a
hard per-image inference deadline. Interrupted runs stay visible in Case attempts.

Observations, derived files and audit records can contain sensitive evidence.
Password parameters are redacted from Case run/attempt records; ledger redaction
covers known secret keys and selected embedded patterns, not every secret in raw
evidence or free text. Keep credentials out of reference/description fields.

The append-only audit ledger records registry executions and hashes, not all host
activity. It is best effort: write/serialization failure does not alter the
examination result. Verify its health and protect an independent seal/anchor when
integrity assurance is required. Hashes establish byte relationships, not truth,
lawful acquisition or immunity to wholesale replacement of both data and anchor.

Use Case coverage before negative findings or handoff. `no_recorded_limitations`
describes recorded execution, not complete acquisition. Report vulnerabilities
through [SECURITY.md](SECURITY.md).
