# Source-linked event sequence hunting

`timeline.hunt_sequences` searches ordered event chains across persisted DFTK
Observation JSON files and inline event bundles. It uses the same normalization
as `timeline.merge` and `case timeline`, without modifying source evidence or
requiring additional packages. It is available through CLI, Python, Case runs,
and the MCP registry adapter.

Run the synthetic example from the repository root:

```bash
dftk run timeline.hunt_sequences --params-file examples/sequences/download-execute-connect.json
```

The example produces one download → execution → connection lead for the same
host and account within 120 seconds. These are illustrative event kinds, not
a universal mapping of every parser's native records. Inspect your actual
`facts.events` fields and write selectors for those fields. This tool performs
correlation; it does not acquire missing artifacts or infer missing events.

## Rule contract

Each rule declares a unique `id`, two to eight ordered `steps`, one to eight
`group_by` fields, and a positive `within_seconds` window (up to seven days).
Optional `severity` is an analyst-supplied label, not a computed risk score.

```json
{
  "id": "logon-process",
  "group_by": ["host", "user"],
  "within_seconds": 300,
  "steps": [
    {"event_id": 4624},
    {"event_id": 4688, "process.name": ["powershell.exe", "cmd.exe"]}
  ]
}
```

Fields within a step are ANDed. A scalar is an exact, case-sensitive match;
a list means any of its values. Dotted fields address nested objects. Values
must be finite JSON strings, numbers, or booleans. Types must match, including
integer versus float. No regular expressions or executable expressions are
accepted. Each selector contains 1–16 fields and each choice list 1–100 values.

Every event in a chain must share all `group_by` values. Missing, null, empty,
or nonscalar join values cannot link events. Times must strictly increase;
equal timestamps do not establish event order. The window applies from first
to last event and includes its boundary. Overlapping matching chains are kept.
A rule can select additional fields, such as the same file hash, when account
and host alone are too broad. Joining only on an account can conflate machines;
choose grouping fields according to the question and available artifacts.

## Inputs and evidence

`files` accepts up to 64 Observation JSON paths; `inline` accepts
`{"source": "label", "events": [...]}` bundles or flat timestamped events.
Use `files` for filesystem input: inline `file` references are rejected, so
inline content cannot bypass MCP path policy.

Normalization accepts Unix seconds in `epoch` or `time`, or ISO-8601 `time`.
Timezone offsets normalize to UTC. Naive timestamps assume UTC and generate a
warning; examine source timezone and clock skew before interpreting order.
Nonfinite, boolean, out-of-range, or invalid timestamps are skipped explicitly.
Event-specific fields and original locators survive normalization. `original_time`
and `time_basis` describe time conversion; confidence is constrained to 0–1.

Each match includes event indices, shared entity values, duration, rule ID,
severity, and input references. `facts.events` contains the normalized records
needed to inspect every step. Evidence items identify the exact input
Observation file and its `facts.events[index]` locator (or detected alternative
facts array), and SHA-256 of the exact bytes parsed. This hash identifies the
input Observation bytes; it does not authenticate their origin or hash the
original acquired disk or database. Existing
artifact locators and hashes remain in the event. Inline input has no file hash.

Match confidence is the minimum normalized input-event confidence; it is not
a probability of compromise. Correlated events may share an original evidence
source. Different source labels do not establish independent corroboration.

## Coverage and limits

- Each Observation read is bounded to 32 MiB. At most 200,000 event records are
  scanned in source order, then normalized valid records are sorted by time.
- `event_limit` (default 200,000) retains the earliest normalized events within
  scanned input. `limit` (default 1,000; maximum 10,000) bounds returned matches.
- At most 32 rules, 10,000 active candidate chains per rule, and 1,000,000
  candidate comparisons per call are permitted. Budget exhaustion stops hunting
  and reports remaining candidates/rules as unexamined.
- Malformed or unreadable inputs, skipped events, timezone assumptions,
  upstream Observation warnings/failure status, truncation, and exhausted budgets produce explicit warnings/errors and
  `partial` status when usable events remain. No usable events plus input read
  errors produces `error`. An empty input without read errors is `partial`.

`facts.coverage` reports scanned, skipped, omitted, and truncated values. A
zero-match result with `partial` coverage cannot establish that no matching
activity exists. The shared `timeline.merge` and Case timeline also expose read
errors and truncation instead of silently presenting incomplete results as OK.
