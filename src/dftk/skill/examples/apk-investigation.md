# Example — APK behavior question

Question: “Does the application upload contacts, and to which endpoint?”

Do **not** treat `READ_CONTACTS` plus an embedded URL as the answer.

Evidence requirement:
1. evidence of contact collection/read path;
2. relationship between collected data and serialization/request/sink;
3. endpoint tied to that request path;
4. runtime/network evidence if the wording requires proof of actual observed transmission.

Use capability discovery for each missing layer. A static, complete data-flow chain may justify SUPPORTED/VERIFIED for implemented behavior depending on wording; permission alone is only a lead.
