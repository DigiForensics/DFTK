# Capability map — DFTK 3.7.0

The registry contains 136 tools (131 READ_ONLY, 5 STATEFUL) — 121 primitives plus 15 recipes. Most capabilities are deliberately narrow so an Agent can compose them according to an evidence requirement.

## Evidence access and media

- `evidence.browse` and `file.read_text` — bounded directory/text access with continuation.
- `media.inspect` — image/EXIF/video metadata without visual disclosure.
- `media.preview` — consent-gated still-image crops or timestamped video frames.
- `media.contact_sheet` — numbered, source-linked thumbnails of up to 16 consented still images.
- `media.ocr` and `media.ocr_batch` — local GPU-first OCR with source boxes/hashes; batch shares model loading and returns unattempted inputs. CPU requires affirmative user consent.
- See [perception contracts and limits](docs/media-perception.md).

## Artifact and filesystem

- `evidence.intake` — Agent-oriented evidence manifest, bounded SHA-256/magic inspection, and source-linked next-step plan for a file or extracted tree.
- `artifact.inspect` — magic/container-aware type identification + SHA-256.
- `tree.inventory` — bounded recursive inventory, extension distribution, largest files.
- `file.hash` — hashlib-backed cryptographic hashing.
- `file.strings` — printable ASCII strings with offsets.
- `file.strings_unicode` — UTF-16LE/BE printable strings with offsets.
- `file.search_tree` — literal/regex search across one file or an extracted tree.
- `timeline.file_metadata` — filesystem mtime/ctime/atime timeline.
- `archive.inventory` — ZIP/TAR member metadata without extraction.
- `archive.extract_safe` — policy-gated workspace extraction with traversal/size guards.
- `timeline.merge` — merge multiple event sources (dftk Observation JSON files or inline events) into one normalized, source-attributed timeline.

## Android

- DEX `string_data_item` parser with ULEB128/MUTF-8.
- APK inventory and DEX search.
- binary AXML `AndroidManifest.xml` parsing.
- package/version, permissions, SDK, application flags and component inventory.
- normalized URL/domain/IP/content-URI endpoint candidates from DEX strings.
- v1 signing-entry plus APK Signing Block v2/v3/v3.1 marker inventory.
- extracted app-data inventory, SharedPreferences parsing and database discovery.

## Native binaries

- ELF architecture/section inventory.
- PE/COFF architecture, timestamp and section inventory.
- bounded JNI/crypto/network/command indicator string scan; explicitly heuristic.
- **Deep PE** (3.5.0): `binary.pe_headers` (DOS/COFF/optional header, data directories, section summary, rich-header presence), `binary.pe_imports` (DLL + imported symbols by name/ordinal, Mandiant-compatible imphash), `binary.pe_exports` (exported symbols + forwarders), `binary.pe_resources` (resource tree walk + embedded manifest extraction), `binary.pe_rich_header` (compiler/toolchain prodid/version/count), `binary.pe_signing` (Authenticode WIN_CERTIFICATE / PKCS#7 with X.509 issuer/subject/validity decoded without external crypto libs; absence of a signature is reported, not assumed malicious).
- **Deep ELF** (3.5.0): `binary.elf_dynamic` (NEEDED libraries, interpreter, RPATH/RUNPATH, GNU build-id, and the dynamic symbol table resolved from `.dynsym`/`.dynstr`).

## Malware and rule scanning

- YARA rule scanning of one file or a bounded evidence tree, using either a rule
  file or inline rule source; source hashes, rule metadata, and bounded match
  offsets are retained without executing the sample.

## Crypto and encoding

- BIP39 English validation and evidence-tree scanning with checksum verification.
- Shannon entropy profiling by bounded blocks.
- hex/Base64/Base64URL/percent decoding candidates.
- `crypto.openssl_decrypt` (STATEFUL) — one supplied-password attempt with explicit cipher/KDF, a key-source citation, bounded execution and inner-format validation before publishing a derived workspace artifact. No guessing or retry loop.

## Linux, Docker and web

- offline OS/account/package-log/web-root/Docker discovery.
- package install/upgrade/remove events.
- SSH authentication and sudo log events.
- cron/systemd/authorized_keys/shell-history persistence candidates.
- offline Docker container config and json-file logs.
- web/application config candidate discovery and explicit config key/value extraction with secret redaction by default.
- Nginx/Apache access-log summaries.
- fixed-command read-only SSH inventory behind network policy.
- remote SSH forensic snapshot profiles for baseline, incident response, container, and web-server evidence: host key fingerprint, identity, sessions, processes, listeners, routes, systemd, timers, cron, persistence paths, auth-log tail, Docker, and web exposure—without an arbitrary command parameter.
- bounded WebShell hunting for PHP/JSP/ASP/ASPX/Node/Python source trees, with
  source hashes and byte offsets for suspicious input-to-execution/obfuscation combinations.

## Databases

- immutable read-only SQLite schema/count inventory.
- bounded `SELECT`/`WITH` SQLite query with engine-level authorizer.
- generic SQL text-dump database/table/INSERT activity inventory.
- bounded cross-table/column literal search via `database.sqlite_search`.

## Network captures

- classic PCAP flow inventory.
- PCAPNG SHB/IDB/EPB/SPB inventory for Ethernet IPv4 TCP/UDP.
- DNS question extraction.
- HTTP/1 request method/target/Host extraction.
- best-effort TLS ClientHello SNI extraction when the ClientHello is available in a single parsed TCP payload.
- `network.flows` — group packets into TCP conversations and UDP 5-tuples with counts/timestamps/flag summary.
- `network.tcp_reassemble` — reassemble each TCP stream direction by sequence (retrans/out-of-order/overlap handled), SHA-256 + bounded hex preview. READ_ONLY.
- `network.http_sessions` — correlate HTTP request/response pairs and extract file-like response bodies to the workspace as DerivedArtifacts. STATEFUL.
- `network.dns_transactions` — correlate DNS query/response by transaction id + name, resolving A/AAAA/CNAME.
- `network.tls_inventory` — SNI / ALPN / versions / cipher suites / extensions / JA3 from TLS ClientHello.

## Windows

Native, dependency-free Windows host-artifact tools (pure-Python, work on student machines):

- `windows.mft` — NTFS `$MFT` path rebuild, SI/FN timestamps, flags, size.
- `windows.prefetch` — `.pf` (v17/23/26/30) executable, hash, run count, last run, referenced files.
- `windows.lnk` — Shell Link target, timestamps, TrackerDataBlock machine/MAC.
- `windows.recyclebin` — Recycle Bin `$I` original name, size, deletion time, paired `$R`.
- `windows.usnjrnl` — `$UsnJrnl:$J` change journal (V2/V3): FRN, parent FRN, reasons, source info, attributes; optional `$MFT` FRN→path resolution. Reports file-system activity factually — does **not** infer execution.

Optional `python-registry` / `python-evtx` capabilities:

- Registry hive inventory (pure-Python fallback when `python-registry` is absent).
- Pure-Python live key tree (`windows.registry_tree`) and deleted/unreachable key recovery (`windows.registry_deleted_keys`).
- SYSTEM hive CurrentControlSet USBSTOR and MountedDevices recovery.
- EVTX provider, EventID and timestamp summaries.
- Deep EVTX hunting: normalized event timeline plus high-value logon, process,
  PowerShell, service-install, scheduled-task, audit-clear, and Sysmon triage hits.

Program / execution-context artifacts (3.5.0):

- `windows.amcache` — `Amcache.hve` parsed with the pure-Python REGF reader: file records (path, SHA1, size, version, last-modified, linked ProgramId) and `InventoryApplication` program metadata.
- `windows.shimcache` — AppCompatCache entries (path + last-modified). Execution is **not** inferred: every entry carries `execution_inference = "unsupported"`; correlate with Prefetch / Amcache / `$MFT` / USN instead.
- `windows.srum` — `SRUDB.dat` (ESE) usage tables via the `esedb` adapter; returns `UNSUPPORTED` when the optional ESE reader is absent.

## Memory forensics

DFTK does not re-implement a memory engine. `memory.*` is a **fixed-capability
adapter** over Volatility 3 — six tools, one plugin each, no arbitrary arguments
(the same philosophy as `server.remote_snapshot`):

- `memory.volatility_inventory` (`windows.info`) — system overview.
- `memory.processes` (`windows.pslist`) — process list.
- `memory.network` (`windows.netscan`) — network connections.
- `memory.malfind` (`windows.malfind`) — injected / anomalous memory regions.
- `memory.modules` (`windows.modules`) — kernel modules.
- `memory.handles` (`windows.handles`) — open handles.

Every run is bounded by a timeout and row limit, treats the dump as read-only
evidence, and normalises output into an `Observation` carrying the source hash.
When Volatility is absent the tools return `UNSUPPORTED` instead of failing.

## Disk images

Optional forensic-environment capabilities:

- E01/EWF segment and acquisition metadata through `pyewf`.
- E01 partition/filesystem root inventory through `pyewf + pytsk3`.

## Browsers

- Chromium/Chrome/Edge URL/visit history.
- Chromium download records and URL chains.
- Chromium cookie metadata, optional plaintext values, and encrypted-value hashes/lengths without decryption.
- Firefox `places.sqlite` visits.
- `browser.chromium_bookmarks` — bounded Bookmarks JSON with folder paths, JSON-pointer locators, added/modified/last-used timestamps; embedded browser checksum is not verified.
- `browser.firefox_bookmarks` — `moz_bookmarks` joined to `moz_places`, preserving folder ancestry, GUIDs and creation/modification times.
- `browser.firefox_cookies` — cookie metadata, container/partition origin attributes, optional plaintext values, Unix second/microsecond time conversion; values are hidden by default.
- `browser.chromium_search_terms` — keyword search records with URL context; URL last-visit time is not an exact search timestamp.

The new SQLite readers use immutable main-database views. A WAL/journal sidecar
marks the result `partial` because uncheckpointed changes are excluded. Row,
text-field, JSON byte/depth, and SQLite instruction bounds prevent unbounded
record materialization. Limits and malformed bookmark nodes produce explicit
warnings. Bookmark presence, cookie presence and recorded search terms do not
establish local-user attribution or a completed authenticated action.

## Email

- offline From/Sender/Return-Path/DKIM/Authentication-Results context.
- MIME structure and attachment SHA-256 inventory.
- network-gated DKIM verification and SPF evaluation.

## Timeline correlation and case sessions

- `correlation.entity_graph` — source-linked domains, IPs, email addresses, SHA-256 values, and account identifiers across DFTK Observations; includes deterministic co-observation relationships.
- `timeline.hunt_sequences` — bounded ordered event-chain hunting with exact-field selectors, shared entity keys, source hashes/locators, and explicit incomplete-coverage status. See [usage](docs/sequence-hunting.md).
- `timeline.merge` — pure correlation primitive: normalize ISO/epoch timestamps, sort, and attribute events to their source across multiple inputs.
- `dftk case graph <case_id>` / MCP `dftk_case(action="graph")` — derive the same entity graph directly from persisted Case Observations.
- `recipe.timeline.unified` — compose a filesystem metadata timeline (and optional extra sources) into one unified timeline.
- `dftk case` CLI — accumulate read-only tool runs in an isolated workspace (`.dftk/cases/<id>/`) and correlate them: `case new`, `case list`, `case run`, `case timeline`, `case export` (JSON or Markdown). The session only writes under its explicit workspace and never touches source evidence.

## Chain of custody

- `custody.ledger_verify` — recompute the audit ledger's per-record SHA-256 hash chain and report records that were edited, deleted, reordered, truncated or downgraded; optionally compare the ledger against a seal. Read-only. A status of `ok` means the verification ran; read `facts.verdict` for the result.
- `dftk audit verify <ledger.jsonl> [--seal seal.json]` — the same check from the CLI. Exit 0 intact, 1 defective, 2 unreadable.
- `dftk audit seal <ledger.jsonl>` — write an external anchor (record count, last record hash, whole-file SHA-256) so deletion from the *end* of a ledger is detectable; a defective ledger refuses to seal.

## Recipes

- `recipe.artifact.auto_triage`
- `recipe.android.static_triage`
- `recipe.android.deep_static_triage`
- `recipe.android.appdata_triage`
- `recipe.server.offline_triage`
- `recipe.server.deep_offline_triage`
- `recipe.network.capture_triage`
- `recipe.database.triage`
- `recipe.windows.offline_triage`
- `recipe.browser.history_triage`
- `recipe.email.offline_triage`
- `recipe.email.full_offline_triage`
- `recipe.wallet.mnemonic_scan`
- `recipe.timeline.unified` — build a unified, source-attributed timeline from a filesystem tree plus optional extra dftk Observation sources.

## Reporting, verification and application profiles

- `case.report_html` (STATEFUL) — self-contained HTML forensic report: case summary,
  evidence sources, observations, recovered artifacts, timeline, entities,
  warnings/limitations, chain of custody and tool manifest. Every rendered value is
  escaped; the report is registered as a DerivedArtifact. HTML first — PDF can be
  layered on without changing the report model.
- `case.verify` — replays an audit ledger and reports `VALID` or `BROKEN` with the
  failing record number and reason; re-derives each record's result and evidence
  digests, and cross-checks supplied observations / manifest.
- Application Profile architecture (`dftk/profiles/`) — a declarative
  `ArtifactProfile` describing detection conditions, database location, table/field
  mapping, time format, encoding and attachment relations. `application.profile_list`
  enumerates profiles; `application.profile_apply` detects or applies one and
  normalises rows (databases opened read-only). An unmatched schema is reported, not
  guessed. Ships one validated demo profile (generic Android messaging); vendor IM
  parsers become profile *data* in 3.6 rather than bespoke parser code.

## Release-wide execution and verification (3.6)

- Contracts validate declared JSON parameter types, enum values, and explicit bounds before execution. Caller dictionaries are copied.
- Host paths advertise EVIDENCE_INPUT, WORKSPACE_OUTPUT, WORKSPACE_INPUT, or ANALYSIS_INPUT. ANALYSIS_INPUT reads observations/rules/seals under either evidence or workspace roots; filesystem-internal paths remain opaque.
- Recipes inherit the parent safety/network/root policy, including child calls that supply a new policy. Directory walks skip symlinks; bounded reads enforce the ceiling on the actual read.
- Audit records include observation, result, parameter and evidence digests, including derived artifacts. New and legacy chains share verification, locking and sealing.
- Cases record persisted artifact SHA-256 and evidence-content digests for findings; integrity checking catches value-only edits. Finding registration shares the per-case process/thread lock.
- Runtime readiness resolves external binaries through the DFTK toolchain. Static manifests omit machine-specific readiness; request `export-manifest --runtime-readiness` for an environment snapshot.

## Mach-O and binary comparison

- `binary.macho_inventory` — thin 32/64-bit, both byte orders, and universal 32/64 architecture tables. Inventory dylibs, rpaths, UUIDs, segments and bounded symbol records. Invalid slice ranges and load commands stay explicit. Code-signature presence does not establish cryptographic validity.
- `binary.compare` — stream two bounded inputs by fixed byte offsets, calculate each source's SHA-256, and return complete changed-block counts with bounded previews. Insertions may shift later blocks; this is a byte comparison, not semantic equivalence.
