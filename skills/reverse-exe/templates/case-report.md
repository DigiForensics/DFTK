# Case report — executable reverse engineering

Consolidated output for one sample. Keep findings ordered by the original
question numbering, but do **not** embed answer values here if this report will
be shared as a skill — keep answers in private case notes and present only the
method/structure.

```
# Reverse / EXE analysis report — <sample name / sha256>

## 1. Evidence
- Source: <evidence path / how obtained>
- SHA256: <hash>
- Working copy: <path>; original untouched.

## 2. Recon summary
- Packer/compiler: <…>
- Behavior classes: injection=<Y/N>, screenshot=<Y/N>, crypto=<linked lib>
- Entropy hotspots: <section/offset>

## 3. Findings (one claim card per question)
### Q<N>
<paste templates/claim-card.md content; level + evidence + method>

### Q<N>
...

## 4. Open items
- <what remains UNRESOLVED and why: e.g., runtime-decoded config key>
- <recommended next step: IDA/Ghidra or sandbox API trace>

## 5. Verification roll-up
- VERIFIED: <count>
- SUPPORTED: <count>
- CANDIDATE/UNRESOLVED: <count>
```

Rule: a finding is only as strong as its weakest link. If the key was
runtime-decoded and not recovered, mark the dependent claims UNRESOLVED rather
than guessing.
