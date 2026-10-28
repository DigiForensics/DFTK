# Architecture

DFTK 3.7.0 is a capability runtime with CLI, Python and MCP adapters. Its companion
Skill is investigation guidance. The host Agent owns planning and scheduling;
DFTK does not contain a general autonomous task graph or a mandatory investigation
workflow. Native parsing, perception and derived outputs share one result contract.

## Runtime components

| Component | Responsibility |
|---|---|
| `catalog.py`, `primitives/`, `recipes/` | Load bounded operations and optional compositions |
| `core/registry.py`, `core/models.py` | ToolSpec discovery, argument validation, policy, execution and Observation/Evidence contracts |
| `core/safety.py`, `core/path_policy.py` | Capability/network policy, declared host-path roles and inherited recipe restrictions |
| `mcp_server.py`, `mcp_worker.py` | Eight stdio meta-tools, bounded replies, worker deadline and native image transport |
| `core/case.py` | Per-run persistence, attempts, evidence memory, derived-input registration, findings and context/coverage views |
| `core/provenance.py`, `core/audit.py` | Derivation relationships and best-effort hash-chained execution records |
| `core/readiness.py`, `core/external_tools.py`, `doctor.py` | Dependency/toolchain discovery and diagnostics |
| `profiles/` | Declarative application-artifact detection and row normalization |

The CLI and public `get_registry()` / `run_tool()` entry points use the same
registry as MCP. Only MCP supplies its worker isolation and server-owned roots
automatically. Direct Python/CLI invocations do not inherit that process policy.

## Capability contract

Each ToolSpec declares a name, description, JSON-compatible parameters, safety,
network requirement, tags, produced types, optional requirements, determinism/cost
hints and path roles. Declared types/enums/bounds are validated before work.
Hints aid selection; they are not guarantees of input support, output accuracy or
cross-environment reproducibility. Static manifests omit machine-specific readiness.

A primitive performs one operation; a recipe composes operations and aggregates
results. Repeated child tool names receive unique fact keys instead of overwriting
each other. Child calls inherit the active parent policy and cannot raise its
ceiling or replace its roots/derived permissions. Guided Case intake persists
selected children separately; ordinary Recipe children remain within the aggregate.

## Evidence and derivation

An Observation includes status, summary, facts, evidence, warnings, errors,
metadata and derived artifacts. Evidence identifies a source, locator, kind/value,
method, optional confidence/hash and derivation linkage. The registry propagates
a known source hash only when an item has none; batch media assigns per-source
hashes explicitly. Empty hashes or missing locators are not invented.

DerivedArtifact nodes can carry concrete output paths. Known root digests
participate in root identity so equal basenames do not merge distinct acquisitions.
Historical IDs still load. A derivation DAG records byte relationships and method
parameters; it is not independent proof of content interpretation or acquisition.

Case manifests register intact derived files only within the workspace. Subsequent
EVIDENCE_INPUT validation accepts exact registered paths after digest checks.
Arbitrary files under that workspace do not become source evidence automatically.
Outputs can form further derivations under the same Case.

## Safety model

131 tools are READ_ONLY (136 registered in total); five are STATEFUL and none
are DESTRUCTIVE. The workspace writers are `archive.extract_safe`,
`crypto.openssl_decrypt`, `filesystem.extract`, `network.http_sessions` and
`case.report_html`. READ_ONLY capability execution may still persist a Case/audit
record. Network gating is independent of the safety level.

Path roles separate evidence, workspace output/input and analysis material. MCP
uses a source root and an outside writable workspace by default. It does not
expose DESTRUCTIVE as a launch ceiling or let tool arguments change server policy.
All of this is an application boundary, not an OS sandbox. [Safety](SAFETY.md)

MCP capability execution uses a child process with stdout/stderr separated from
JSON-RPC framing. The parent enforces a worker deadline and records Case failures
when the worker times out/crashes. Case updates use process/thread locks and
atomic manifests; the server serializes worker execution. There is no global
Agent-call deduplication or investigation-wide attempt budget.

## Perception transport

Discovery and metadata do not disclose pixels. Preview/contact-sheet operations
check host-supplied scoped consent and image-model capability attestations before
decoding. Local OCR has an independent GPU/CPU execution contract.

Observation `presentation` carries bounded images for transport only and is
excluded from `to_dict()`. Workers return it separately; the adapter builds a
native CallToolResult with image blocks plus structured metadata. SDK result-schema
inference is disabled for these explicitly constructed results, including on
Python 3.10. Case JSON, exports and result paging do not replay pixels.

Video is requested timestamp sampling, not continuous/audio analysis. OCR retains
raw text and coordinates; CPU requires affirmative consent and weights are
provisioned before examination. [Perception contract](docs/media-perception.md)

## Cases, integrity and limits

Case storage is `<workspace>/cases/<id>/`: manifests, numbered Observation JSON,
attempt records, source/derived inventory and optional findings. A brief restores
bounded context; coverage combines recorded limits, pending actions, unread items,
interrupted attempts and stored-result integrity checks. Analyst dispositions are
assertions, not proof of review. Graph/timeline views are correlation products.

The audit ledger records registry executions, redacted parameters, result/evidence
digests and chain links. It is separate from Evidence and does not log arbitrary
host shell work. Failures in audit I/O do not change the examination result.
Independent seals/anchors are needed for stronger integrity assurance.

Tests exercise contract and source-preservation invariants on fixtures. They do
not certify forensic correctness across every format, host UI, decoder, optional
engine or real case. [Validation details](docs/agent-reliability.md)
