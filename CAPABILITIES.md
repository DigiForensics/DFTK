# Capability map — DFTK 3.2.1

The registry contains 72 tools (71 READ_ONLY, 1 STATEFUL). Most capabilities are deliberately narrow so an Agent can compose them according to an evidence requirement.

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

## Windows

Optional `python-registry` / `python-evtx` capabilities:

- Registry hive inventory.
- SYSTEM hive CurrentControlSet USBSTOR and MountedDevices recovery.
- EVTX provider, EventID and timestamp summaries.

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
