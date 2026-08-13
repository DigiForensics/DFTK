# Evidence model

DFTK separates tool execution from forensic interpretation. Preserve that separation.

## Observation
An Observation is the complete result of one DFTK capability:

- `status`
- `summary`
- `facts`
- `evidence[]`
- `warnings[]`
- `errors[]`
- `meta`

`ok` means execution succeeded, not that every possible conclusion is proven.

## Evidence strength

### Direct evidence
The source field/record/event directly expresses the requested fact.
Example: an authentication event explicitly ties account, timestamp, and remote IP.

### Structural evidence
A parser exposes a relationship inherent in the artifact structure.
Example: SQLite foreign-key-compatible IDs connect a message row to an account row.

### Behavioral/code-path evidence
Code/configuration establishes an implemented flow. Strong for capability claims; actual execution may require runtime/event corroboration.

### Corroboration
An independent source supports the same claim or validates a weak link.

### Lead
A string, identifier, endpoint, timestamp, or anomaly worth following but not sufficient alone.

## Provenance
When DFTK returns Evidence, preserve:

- `source`
- `locator`
- `value`
- `source_sha256`
- `method`
- `confidence`

Do not manufacture missing fields. A source hash anchors the source used by the tool; it does not by itself prove semantic interpretation.

## Evidence chain
For multi-hop claims, write the chain explicitly and test the weakest hop. Example:

```text
contacts API call
→ returned records passed to serializer
→ serializer output passed to request body
→ request targets endpoint X
```

If only the first two hops are proven, do not report the fourth as VERIFIED.
