# Example — multi-question server investigation (method only)

A simulated Linux web server (reached over SSH) hosts several applications. A set of competition-style questions asks for exact values drawn from partition metadata, config files, live databases, an encrypted archive, and container state.

This example shows the full **claim → evidence → capability → execute → verify** pass, run read-only. It demonstrates the *method*. Do not embed the actual exam questions or answers in a shared skill — keep those with the exam material.

## Access

- SSH as a low-privileged or root account; read-only by default.
- Commands used: `blkid`, `ss`, `ps`, `docker ps/inspect/exec`, `mysql` (via `docker exec`), `sha256sum`, `grep`/`cat`.
- Keep every command `SELECT` / read-only; never mutate evidence.

## Triage (recon.md)

```text
blkid                 -> partition + filesystem UUIDs
docker version        -> server version
ss -tlnp              -> listening ports + owning process
docker ps -a          -> containers, published ports, mounts, status
locate app roots      -> /root, /srv, /opt, docroots; scope grep to the app dir (no find /)
```

Build one inventory and reuse it across questions.

## How each question type was answered (technique, not answers)

**Partition identity.** "Last 8 chars of `sda3` PARTUUID, uppercase" → `blkid /dev/sda3`, take the `PARTUUID`, strip `-`, last 8 hex, upper-case. Distinguish `PARTUUID` (partition table) from filesystem `UUID`. See `references/partition-identity.md`.

**External-port ambiguity.** A DB service runs in a container publishing `HOST:3399->3306`. The app connects to `3306` (container port); an external client reaches `3399` (host-published). When the wording says "对外端口", report the host-published port and note the container port. Always state both when they differ. See `references/service-port-enum.md`.

**Web-config credential.** A "DB password" / "config filename" question → `grep -rniE "dbhost|dbuser|password|dsn"` in the app root; read the matched file; report the value and the file basename. See `references/web-config-review.md`.

**PII by stable key.** A "phone/email of person X" question → the name may be mojibake in the dump, so a name `LIKE` returns nothing. Search by `mtel`/`memail` (or a Latin account id) instead, then read back the target field. See `references/live-db-forensics.md`.

**Aggregation.** A "total amount" question → `SELECT SUM(col)` with an explicit predicate; convert units for the answer format and show the raw sum. See `references/live-db-forensics.md`.

**Encrypted archive.** An "algorithm + password" question → identify `Salted__`, recover cipher+password by successful decrypt, verify with `tar tzf`. See `references/encrypted-archive.md` and `examples/encrypted-archive-decrypt.md`.

**Container DB.** A stopped evidence container → `docker start` it read-only, then `docker exec mysql` over the container loopback (host-bridge connections are often denied by the grant). `SELECT` only. See `references/container-evidence.md`.

**Group ownership / table name.** Join `owner_id -> user.id`; enumerate `information_schema.tables` to find the chat table. See `references/live-db-forensics.md`.

## Skill gaps this case exposed

The toolkit's 68 read-only tools did not cover any of the above; all answers came from shell tooling. The blind spots (now covered by this skill's references):

1. Partition identity — `blkid` PARTUUID (partition-identity.md).
2. Web/app config & credential review — read PHP/YAML/HTML for DSN, password, business identifiers (web-config-review.md).
3. Live RDBMS forensics — MySQL enumeration, PII by stable key, aggregation, hash-format detection (live-db-forensics.md).
4. Encrypted-archive ID & decrypt — OpenSSL `Salted__`, `aes-256-cbc`, password recovery (encrypted-archive.md).
5. Service/port enumeration & "对外端口" meaning — host-published vs container vs ingress (service-port-enum.md).
6. Containerized evidence access — `docker inspect/exec`, volume MySQL, bridge-auth gotcha (container-evidence.md).
7. SSH live-forensics workflow — read-only remote investigation, provenance (ssh-live.md).

## Takeaways for the next server case

- Triage once; reuse the inventory across questions.
- When a name search returns nothing, switch to a stable alternate key (email/phone/account id) — encoding mojibake is common.
- The "externally reachable" port is the host-published/ingress port, not the container port. State both when they differ.
- For encrypted archives, identify `Salted__` first, then recover cipher+password by successful decrypt; verify with `tar tzf`.
- Keep every command read-only; note any container you had to start for read access.
