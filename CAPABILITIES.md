# Capability map — DFTK 3.5.0

The registry contains 99 tools (95 READ_ONLY, 4 STATEFUL) — primitives plus recipes. Most capabilities are deliberately narrow so an Agent can compose them according to an evidence requirement.

## Artifact and filesystem

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

## Crypto and encoding

- BIP39 English validation and evidence-tree scanning with checksum verification.
- Shannon entropy profiling by bounded blocks.
- hex/Base64/Base64URL/percent decoding candidates.

## Linux, Docker and web

- offline OS/account/package-log/web-root/Docker discovery.
- package install/upgrade/remove events.
- SSH authentication and sudo log events.
- cron/systemd/authorized_keys/shell-history persistence candidates.
- offline Docker container config and json-file logs.
- web/application config candidate discovery and explicit config key/value extraction with secret redaction by default.
- Nginx/Apache access-log summaries.
- fixed-command read-only SSH inventory behind network policy.

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

## Email

- offline From/Sender/Return-Path/DKIM/Authentication-Results context.
- MIME structure and attachment SHA-256 inventory.
- network-gated DKIM verification and SPF evaluation.

## Timeline correlation and case sessions

- `timeline.merge` — pure correlation primitive: normalize ISO/epoch timestamps, sort, and attribute events to their source across multiple inputs.
- `recipe.timeline.unified` — compose a filesystem metadata timeline (and optional extra sources) into one unified timeline.
- `dftk case` CLI — accumulate read-only tool runs in an isolated workspace (`.dftk/cases/<id>/`) and correlate them: `case new`, `case list`, `case run`, `case timeline`, `case export` (JSON or Markdown). The session only writes under its explicit workspace and never touches source evidence.

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
