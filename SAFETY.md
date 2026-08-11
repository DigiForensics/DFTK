# Safety policy

The default execution policy is evidence-preserving and offline.

## Levels

- `READ_ONLY` — reads evidence, metadata or immutable / read-only database connections; fixed remote inventory also belongs here but is separately network-gated.
- `STATEFUL` — writes only to a derived workspace or otherwise changes runtime state without modifying the source evidence.
- `DESTRUCTIVE` — writes / deletes target evidence, rewrites configuration, stops / starts services, installs software, pulls / runs containers or exposes arbitrary target-shell mutation.

DFTK 2.1 registers **65 READ_ONLY**, **1 STATEFUL** and **0 DESTRUCTIVE** tools.

The one stateful tool, `archive.extract_safe`, writes to an explicit output directory and is blocked under the default policy. It applies path-traversal, member-count and expanded-size checks and does not modify the source archive.

## Network isolation

Network-capable tools are disabled unless the caller opts in with `--allow-network`. This prevents an offline run from unexpectedly performing DNS or SSH traffic.

Current network-gated capabilities are DKIM verification, SPF evaluation and fixed-command SSH inventory. SSH does not expose an arbitrary command parameter and rejects unknown host keys.

## Databases

SQLite forensic access uses URI `mode=ro&immutable=1` plus `PRAGMA query_only=ON`. `database.sqlite_query` adds a SQLite authorizer and only accepts a single `SELECT` / `WITH` statement; write / DDL operations are denied by the engine even if a query attempts to hide them behind SQL syntax.

## Archives

Archive inventory never extracts. Controlled extraction is `STATEFUL` and rejects members that resolve outside the selected output directory. TAR links / special members are not materialized by default.

## Specialist parsers

When `python-registry`, `python-evtx`, `pyewf`, `pytsk3`, `dkimpy`, `pyspf` or `paramiko` are absent, the matching capability returns `UNSUPPORTED` rather than silently pretending a weaker parser is equivalent.

## Legacy scripts

The original competition archive is retained only for provenance and knowledge mining. It is not imported by the registry. Historical scripts that contain credentials, target addresses, fixed challenge entities or state-changing commands must not be exposed to an autonomous Agent.
