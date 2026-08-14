# Claim card

One claim per card. Keep answers out of shared skill copies; embed only in
private case notes.

```
claim:        <what was asked>
evidence:     <exact artifact: manifest line / source:line / .so offset / filter>
capability:   <tool that produced it: jadx / unzip / strings / tshark>
method/hash:  <sha256 of the APK or .so when available>
verification: VERIFIED | SUPPORTED | CANDIDATE | UNRESOLVED | UNSUPPORTED
reasoning:    why this evidence proves the requested claim
limitations:  only when material
```

For competition-style multi-question tasks, preserve the original numbering and
do not bury the exact answer inside prose.
