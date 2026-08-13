# Tool selection and replanning

## Search from the gap
Search DFTK capabilities for the evidence type needed, not for the answer you hope to find.

Good search intents:
- Android endpoint configuration / executable URL use
- authentication event remote IP
- SQLite schema and account relationship
- PCAP HTTP/DNS/TLS evidence
- filesystem timestamp inventory

Weak search intents:
- “answer question 7”
- the expected answer string copied from a guess

## Describe before run
Check:
- exact parameter names/types;
- declared safety level;
- whether network is required;
- `produces` and tags;
- optional parser requirements;
- cost hint.

## Selection preference
When several capabilities could help:
1. prefer artifact-native structured parsers;
2. prefer direct evidence over broad discovery;
3. prefer low-cost bounded operations;
4. use string/byte search to discover candidates or when structured parsing cannot reach the target;
5. use a different evidence source for corroboration rather than repeating equivalent searches.

## Replanning
After an Observation, update the evidence gap. Replan when:
- the artifact type differs from expectation;
- a parser is unsupported;
- a candidate reveals a stronger structured source;
- warnings show incomplete coverage;
- the result disproves the current hypothesis.

Do not repeat an equivalent action with only cosmetic query changes unless the changed query tests a distinct hypothesis.
