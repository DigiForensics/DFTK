# Architecture

## Public tool boundary

The registry is the only capability surface intended for an Agent. Each `ToolSpec` declares:

- stable tool name and plain-language description;
- JSON-compatible parameters;
- safety class and whether network access is required;
- semantic tags;
- evidence/fact types the tool produces;
- optional runtime dependencies;
- deterministic flag and a coarse cost hint.

This lets an upper layer select tools from evidence requirements instead of script filenames.

```text
Question / AnswerIntent / EvidenceRequirement
                  |
                  v
          Agent / TaskGraph Runtime
                  |
          find by tags / produces
                  |
                  v
             ToolRegistry ----------> SafetyPolicy
                  |
       +----------+-----------+------------------+
       |          |           |                  |
  artifact/fs  platform   protocol/data     optional expert parsers
       |          |           |                  |
 file/search   Android     DB / PCAP          E01/TSK
 timeline      Linux       browser/email      Registry/EVTX
 archive       Windows     crypto/encoding    SSH/DNS
       +----------+-----------+------------------+
                  |
                  v
             Observation
       facts + evidence + status
                  |
                  v
             EvidenceStore
```

## Evidence contract

`Evidence` records:

- `source` — file/URI/artifact where the observation came from;
- `locator` — byte offset, DEX string id, SQLite object, MIME part, packet number, registry path, log line or equivalent;
- `kind` and `value`;
- `source_sha256` when the source hash is available without extra acquisition work;
- `confidence` in the range 0..1;
- `method` and an optional note.

The registry propagates a known source SHA-256 from observation metadata into evidence items that do not already carry one. An upper-layer evidence store can therefore construct immutable evidence nodes without scraping terminal output.

## Audit ledger boundary

`core/audit.ToolAuditLog` is an optional append-only JSONL side record wired into the single `registry.run` funnel, so every execution path — CLI, recipe, `CaseSession`, MCP worker — is covered by one implementation rather than per-caller logging.

The ledger is outside the evidence contract. It records run provenance (timestamp, tool, caller, parameters, safety level, status, evidence hashes, and errors) and does not produce `Evidence`. Serialization and I/O failures do not change the examination result.

## Safety model

`READ_ONLY < STATEFUL < DESTRUCTIVE`.

The default policy allows only `READ_ONLY` and disallows network traffic. Currently:

- 71 tools are `READ_ONLY` (72 registered in total);
- `archive.extract_safe` is `STATEFUL` because it writes a derived workspace while leaving the source archive unchanged;
- no registered tool is `DESTRUCTIVE`;
- network-capable tools are separately gated.

Historical scripts that edit target files, stop/start services, rewrite panel state, execute arbitrary shell commands or launch containers remain outside the registry.

## Primitive vs recipe

A primitive performs one bounded forensic operation. A recipe composes primitives but does not embed challenge answers or target-specific constants.

Examples:

- `network.capture_protocols` is a primitive;
- `recipe.network.capture_triage` combines artifact identification, format-appropriate flow inventory and protocol extraction;
- `recipe.server.deep_offline_triage` combines package, authentication, persistence, Docker, web config/log and optional literal-search observations over an offline root filesystem.

`recipe.artifact.auto_triage` is deterministic and conservative. It provides a baseline; follow-up actions still depend on the question and accumulated observations.

## Optional dependency semantics

A capability that depends on a specialist parser must return `UNSUPPORTED` with an explicit dependency requirement when that parser is absent. It must not silently fall back to low-quality string guessing while retaining the same tool name.

This rule is used for E01/TSK, Windows Registry/EVTX, DKIM/SPF and SSH integrations.

## Promotion rule

A legacy technique becomes a registered primitive only when:

1. case constants are removed or converted to parameters/discovery;
2. output is structured facts/evidence, not print-only text;
3. parse/IO failures remain explicit;
4. safety and network behavior are declared;
5. bounds exist for potentially large scans;
6. a regression test covers the promoted behavior.

## Native MCP boundary (3.1)

The MCP server is an adapter, not a new forensic runtime:

```text
Host Agent
    |
    | stdio MCP (6 meta-tools)
    v
DFTK MCP adapter
    |  server-owned root / SafetyPolicy / network gate / timeout
    v
ToolRegistry -------- CaseSession (optional persistence)
    |
    v
Observation / Evidence
```

MCP capability execution is delegated to an isolated worker process. The parent server keeps stdout reserved for JSON-RPC framing and serializes runs so CaseSession's manifest update sequence is not raced by concurrent Agent requests.

The MCP tool schema deliberately omits `allow_network` and safety-escalation arguments. Those are server launch policy. `DESTRUCTIVE` is not an accepted MCP ceiling. Paths passed to capabilities are constrained to the server owner's `--root`. Large model-facing responses are bounded; full large Observations should be persisted in a DFTK case and paged through the case-run reader.

The Agent remains responsible for question decomposition, evidence requirements, hypothesis management, verification and stopping. Those methods live in `DFTK-skill`, not in the capability runtime.
