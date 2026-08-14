# Server forensics case report

## Target

- Host: `<ip / hostname>` (reachable via: SSH / local shell)
- Access level: `<user, read-only>`
- Scope: `<which apps / containers / questions>`

## Access & safety

- Access method: `<ssh user@host / docker exec>`
- Read-only enforced: `<yes; SELECT / cat / grep / blkid / ss / docker inspect+exec only>`
- State changes: `<none, or note any container started for read access>`

## Triage (inventory)

- OS / kernel:
- Disks / partitions (PARTUUID of interest):
- Listening ports + owning process:
- Containers (names, published ports, mounts, status):
- Application roots + config paths:

## Findings (one claim card per question, keep original numbering)

### <question>

> (paste `templates/claim-card.md` per question)

## Divergences / assumptions

- `<where the answer wording is ambiguous, e.g. external vs container port>`
- `<which ports/values stated both ways>`

## Reproducibility

- Commands recorded per finding above.
- For encrypted archives: cipher, password, `tar tzf` listing.
- For DB: `db.table` + row key + column used as locator.

## Summary

- Answered: `<x/y>`
- VERIFIED: `<n>`  SUPPORTED: `<n>`  CANDIDATE/UNRESOLVED/UNSUPPORTED: `<n>`
