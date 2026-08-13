# Claim patterns

Use the claim shape to decide what must be proven before selecting a capability.

## Exact value
Examples: URL, filename, key, package name, version, hash.

A value is VERIFIED when the source and locator establish that the value answers the requested semantic field. A raw string hit is only a candidate when context does not establish its role.

Ask:
- Is the field/record/configuration role explicit?
- Is the value active or merely embedded/dead/example data?
- Does normalization matter (case, encoding, URL form, time zone)?

## Event or time
Examples: first install, login, account creation, execution, transfer.

Need an event whose semantics match the requested event and a timestamp tied to that event. File metadata is not a substitute unless the question explicitly asks for file metadata.

Prefer event-native records/logs over inferred filesystem times. State time zone and timestamp origin when material.

## Count or set
Examples: number of usable accounts, images, domains, records.

Define the predicate before counting. Establish enumeration scope/completeness, deduplicate using the appropriate identity key, then count.

Never silently change “accounts” into “rows” or “usable accounts” into “all records.”

## Identity or relationship
Examples: which developer, which account used an IP, which user sent a message.

Need a stable join key or a sufficiently strong multi-field correlation. Display-name similarity is not enough.

## Behavior
Examples: reads contacts, records audio, uploads SMS, executes persistence.

Use a chain appropriate to the strength of the wording:

```text
capability/permission
→ relevant code/API or artifact
→ data source
→ transformation/control flow
→ sink/action
→ runtime/event corroboration when actual execution is claimed
```

Static evidence can establish implemented capability or a strongly supported code path; do not automatically phrase it as observed execution.

## Infrastructure attribution
Examples: backend URL, historical login IP, operator server.

Separate:
1. string/config presence;
2. actual use;
3. event/session linkage;
4. ownership/operator attribution.

Each is a stronger claim than the previous one.

## Negative claim
Examples: “does not upload contacts”, “no login occurred”.

Requires meaningful coverage of the relevant evidence sources and a successful method capable of detecting the target. `unsupported`, `error`, `blocked`, partial coverage, or a narrow zero-hit query cannot prove absence.

## Chronology
Normalize timestamps, preserve source, and separate observation time from event time. Prefer multiple independent sources when chronology is consequential.
