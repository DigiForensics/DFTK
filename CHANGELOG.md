# Changelog

All notable public changes to DFTK are recorded here.

## 3.5.0 — Forensic Depth Release

> Shift from "能看、能扫、能调用" to "能恢复、能关联、能提取、能证明来源".

Phase 1 — Evidence/Workspace separation & provenance foundation:

- **Path Policy** (`dftk.core.path_policy`): explicit `PathRole` (EVIDENCE_INPUT /
  WORKSPACE_OUTPUT / WORKSPACE_INPUT) declared on every path parameter. The
  `PathPolicy` validator resolves each path (following symlinks/junctions/reparse
  points), rejects UNC and out-of-root escapes, and returns a containment-checked
  `Path`. The registry enforces declared roles whenever the policy carries both
  roots (the MCP server always does); a bare CLI degrades to a best-effort check.
  This replaces the old name-guessing (`path`/`output`/`dest`) and fixes the
  STATEFUL-path gap.
- **Provenance 2.0** (`dftk.core.provenance`): `DerivedArtifact` / `Derivation` /
  `ArtifactRef` model an `Original → Derived → Derived` recovery chain with tool,
  version, locator and hash. `Observation.derived_artifacts` and
  `Evidence.artifact_id`/`derivation` carry the chain; `ProvenanceIndex` serialises
  to JSON. `archive.extract_safe` now registers every extracted member as a
  `DerivedArtifact` so recovered files are provable.
- **Audit Ledger 2.0** (`dftk.core.audit`): every record carries a hash-chain
  envelope (`sequence` / `previous_hash` / `record_hash`) plus content digests
  (`params_digest` / `result_digest` / `evidence_digest`, the last also covering
  derived-artifact hashes). `ToolAuditLog.verify()` replays the chain and returns
  `VALID` or the exact record where it broke. `CaseSession.verify(case_id)` checks
  manifest/artifact integrity and the ledger.
- `SafetyPolicy` gains `evidence_root` / `workspace_root`; `ToolSpec` gains
  `path_roles`. MCP request/worker/case-run now thread the roots so role
  enforcement is real in MCP mode.

Phase 2 — Forensic recovery & extraction (pure-Python parsers, zero external deps):

- **SQLite forensic parser** (`dftk.core.sqlite_forensic`): 100-byte DB header,
  b-tree pages, WAL header/frames with checksum verification, freelist, and
  deleted-record recovery via cell-aware carving + freeblock-clobbered record
  reconstruction. Exposed as `database.sqlite_*` (6 tools).
- **Pure-Python FAT backend** (`dftk.core.fat`, `FatFS`): FAT12/16/32 b-tree
  traversal, cluster-chain walk, directory parse, `read_file`/`list_dir`/`walk`/
  `stat`, and deleted-entry recovery (0xE5 marker). Wired into
  `fs_backend.open_filesystem` as `TSK -> FatFS -> RawFS`, so `filesystem.*`
  works on FAT without pytsk3.
- **Pure-Python E01 reader** (`dftk.core.e01`, `E01BlockSource`): single-segment
  Expert Witness Format (EWF) block source — section-chain walk with per-section
  CRC-32, volume/chunk metadata, table-driven random access, zlib-compressed and
  stored chunks with per-chunk Adler-32 verification. Wired into
  `partition.open_block_source` (magic-byte detection; pyewf only as fallback),
  so the whole `image.partitions -> filesystem.*` pipeline runs on E01 without
  libewf/pytsk3.
- Added 6 `database.sqlite_*` tools and 6 `filesystem.*` tools (the latter
  `filesystem.extract` is correctly `STATEFUL`); registry surface grows by 12
  primitives.

Phase 3 — Windows Registry recovery (pure-Python REGF parser, zero external deps):

- **Pure-Python Registry HIVE parser** (`dftk.core.hive`): parses the REGF base
  block (`regf`), `hbin` blocks, and cells — `nk` (key node), `vk` (value),
  `lf`/`lh`/`li`/`ri` subkey index lists, `sk`/`db`. Builds the live key tree
  from the root (names, LastWrite FILETIME, values, subkey counts) and recovers
  **deleted/unreachable key nodes**: walk the live tree to learn reachable `nk`
  cells, then scan every cell for an `nk` signature that is free or unreachable
  (the `00 6B` tombstone marker is also accepted). Best-effort ancestor path is
  reconstructed from parent pointers.
- **Native Windows registry tools** (`dftk.primitives.windows`): added
  `windows.registry_tree` (pure-Python live-tree inventory) and
  `windows.registry_deleted_keys` (deleted-key recovery). `windows.registry_inventory`
  now **falls back to the pure-Python parser when `python-registry` is absent**, so
  Windows registry inspection is no longer `UNSUPPORTED` on a bare install.
- Registry surface grows by 2 (pure-Python Registry) primitives.

Phase 4 — Network Forensics 2.0 (pure-Python, zero external deps):

The 3.3 tools parsed capture *packets* locally. 3.5.0 builds the next layer —
`Packet -> Flow -> TCP stream -> Protocol session -> DerivedArtifact`:

- **`network.flows`** — groups packets into TCP conversations (canonical
  endpoint-pair key) and UDP 5-tuples with packet/byte counts, timestamps and a
  TCP flag summary.
- **`network.tcp_reassemble`** — reassembles each direction of every TCP stream
  by sequence number, handling retransmission, out-of-order and overlap (earlier
  segment data wins), and emitting a SHA-256 + bounded hex preview of the logical
  byte stream. READ_ONLY.
- **`network.http_sessions`** — reassembles streams, correlates HTTP
  request/response pairs (Content-Length + chunked bodies), and when a response
  body is a file-like object (by content-type or magic: ZIP/PE/ELF/PDF/PNG/…)
  writes it to the workspace as a `DerivedArtifact`. This is the PCAP → download
  → binary-analysis link used by Demo 4. STATEFUL (writes only to workspace).
- **`network.dns_transactions`** — correlates DNS query/response messages by
  transaction id and question name, resolving A/AAAA/CNAME answers.
- **`network.tls_inventory`** — inventories TLS ClientHello records: SNI, ALPN,
  record/client version, supported versions, cipher suites, extensions and a
  JA3 fingerprint (MD5).

Network surface is now 8 tools; full registry (primitives + recipes) is 92.

Phase 5 — Windows USN Journal (pure-Python, zero external deps):

- **`windows.usnjrnl`** — parses an NTFS `$UsnJrnl:$J` change-journal stream
  (USN_RECORD_V2 and V3), recovering per-record File Reference Number (low 48-bit
  MFT entry + 16-bit sequence), parent FRN, USN sequence value, FILETIME, decoded
  `Reason` bitmask, `SourceInfo` and `FileAttributes`. Records are emitted as a
  timeline and summarised by reason. The stream is parsed bounded and read-only.
- **FRN → path correlation** — an optional `mft_path` argument builds a
  `{mft_entry: full_path}` index from a supplied `$MFT` (shared helper
  `build_mft_path_index` in `windows_host`) and resolves each record's FRN to its
  full NTFS path, turning raw journal entries into an attributable activity trail.
- **No execution inference** — USN records are reported factually; the tool does
  not label entries as "executed". Execution inference is left to correlation with
  Prefetch / Amcache / MFT (and to the planned `windows.shimcache`, which must
  likewise avoid over-claiming). This matches DFTK's confidence model.

Windows host surface is now 10 tools (mft, prefetch, lnk, recyclebin, registry_*,
usb_artifacts, evtx_summary, usnjrnl); full registry (primitives + recipes) is 93.

Phase 6 — Deep binary forensics (pure-Python, zero external deps):

- **`binary.pe_headers`** — DOS/COFF/optional header dump, data directories, section
  summary and rich-header presence; decodes subsystem, DLL characteristics and section
  flags.
- **`binary.pe_imports`** — import table: DLLs and imported symbols (by name or
  ordinal), plus a Mandiant-compatible `imphash`.
- **`binary.pe_exports`** — export table: exported symbols with ordinals/addresses and
  forwarded exports.
- **`binary.pe_resources`** — walks the resource tree (type/name/language) and extracts
  the embedded application manifest (RT_MANIFEST).
- **`binary.pe_rich_header`** — decodes the Rich Header: compiler/toolchain product IDs,
  versions and counts (linker, MASM, ImportLib), yielding build provenance.
- **`binary.pe_signing`** — inspects the Authenticode WIN_CERTIFICATE / PKCS#7 blob and
  extracts embedded X.509 certificate issuer/subject/validity via a bounded DER walker
  (no external crypto libs). Absence of a signature is reported, not assumed malicious.
- **`binary.elf_dynamic`** — ELF dynamic metadata: NEEDED libraries, interpreter,
  RPATH/RUNPATH, GNU build-id and the dynamic symbol table (resolved from `.dynsym` /
  `.dynstr`).

All parsers are bounded and read-only; none execute or mutate the binary.

Binary surface is now 11 tools; full registry (primitives + recipes) is 100.

Phase 7 — Windows depth, memory adapter, reporting and profile architecture:

- **`core/regf.py`** — new pure-Python REGF (registry hive) reader. Walks the
  nk/vk/lf/lh/ri/li cell graph with bounded parsing, so hive-based artifacts are
  analysable without `python-registry`.
- **`windows.amcache`** — parses `Amcache.hve` via the new REGF reader: file records
  (path, SHA1, size, version, last-modified, linked ProgramId) plus
  `InventoryApplication` program metadata (name, publisher, version).
- **`windows.shimcache`** — parses the AppCompatCache blob across the entry layouts.
  **Execution is explicitly not inferred:** every entry carries
  `execution_inference = "unsupported"`, and path/timestamp extraction is reported at
  low confidence rather than presented as exact field offsets.
- **`windows.srum`** — adapter over an ESE reader for `SRUDB.dat`; returns
  `UNSUPPORTED` with an install hint when `esedb` is absent. DFTK bundles no ESE
  engine, and does not pretend to.
- **Volatility 3 adapter (`memory.*`)** — six fixed capabilities
  (`memory.volatility_inventory`, `processes`, `network`, `malfind`, `modules`,
  `handles`), each bound to exactly one Volatility plugin with a timeout and row
  limit. **No arbitrary Volatility arguments are exposed** — the same
  fixed-capability philosophy as `server.remote_snapshot`. The image is read-only
  evidence and the result carries the source hash.
- **`case.report_html`** (STATEFUL) — self-contained HTML forensic report: case
  summary, evidence sources, observations, recovered artifacts, timeline, entities,
  warnings/limitations, chain of custody and tool manifest. Every rendered value is
  escaped; the report itself is registered as a DerivedArtifact. HTML first — PDF can
  be layered on without changing the report model.
- **Application Profile architecture** — `dftk/profiles/` with a declarative
  `ArtifactProfile` (detection conditions, db location, table/field mapping, time
  format, encoding, attachment relations) plus `application.profile_list` /
  `application.profile_apply`. Databases are opened read-only and an unmatched schema
  is reported, never guessed. Ships one validated demo profile (generic Android
  messaging); vendor IM parsers become profile *data* in 3.6, not bespoke parsers.
- **`case.verify`** — replays an audit ledger and reports `VALID` or `BROKEN` with the
  failing record number and reason; re-derives each record's result and evidence
  digests, and cross-checks supplied observations / manifest.

- **Five end-to-end demos** (`examples/demos/run_demos.py`) — a release needs more
  than unit tests. Each demo builds small but structurally valid evidence and walks a
  real chain through the registry: (1) SQLite WAL + deleted-record recovery,
  (2) raw image → MBR partition → extract → provenance, (3) `$MFT` + USN + Amcache
  program timeline, (4) PCAP → TCP reassembly → HTTP → recovered PE → binary triage,
  (5) memory dump → Volatility adapter (UNSUPPORTED when absent). All five run under
  an explicit Evidence-Root/Workspace `SafetyPolicy` with an audit ledger, then render
  one HTML report that is verified with `case.verify` (currently: 25 observations,
  ledger VALID).

### Fixed

- **SQLite serial types 5 and 6 were mis-sized** (`core/sqlite_forensic.py`).
  `serial_content_size()` returned the serial type itself for `1..6`, but SQLite
  defines type 5 as a **6-byte** integer and type 6 as an **8-byte** one. Any column
  using them decoded at the wrong width, shifting every column after it, and
  freeblock-clobbered records failed the exact-fit check — so **larger deleted rows
  were never recovered at all**. `serial_content_size()` and `serial_type_value()`
  now follow the spec (regression tests added).
- **Freeblock-clobbered record recovery never worked.** `recover_deleted()` skipped
  the 4-byte freeblock header when hunting the record end (`_next_zero_triple(page,
  i + 4)`) but then passed a window that *still included* it, so `00 00 00 37` was
  parsed as serial types. The window now starts after the header (`page[i + 4:b]`),
  so rows whose cell start was clobbered by a freeblock header are recovered.
- Removed dead code in `profiles._convert_time()` (an `if False else …` branch).
- **REGF nk field offsets were shifted 4–8 bytes** (`core/regf.py`). The 3.5.0
  reader read nk fields at the wrong body offsets (`subkey_count` at `0x18`,
  `subkey_list` at `0x20`, `value_count` at `0x1C`, `value_list` at `0x24`,
  `name_len` at `0x4C`, `name` at `0x50`). The real REGF layout (cross-checked
  against `python-registry`'s `RegistryParse.py`) is `subkey_count@0x14`,
  `subkey_list@0x1C`, `value_count@0x24`, `value_list@0x28`, `name_len@0x48`,
  `name@0x4C`. On a spec-correct hive the old code returned an empty tree
  (silent wrong result), which the synthetic-hive unit tests masked because they
  built hives with the same wrong offsets. Fixed to the canonical layout; the
  nk header guard is now `len(body) < 0x4C`. `windows.amcache` /
  `windows.shimcache` / `registry_*` no longer read empty trees. Independent
  regression tests in `tests/test_regf_offsets.py` build hives at the canonical
  offsets and also assert the *old* offsets fail.
- **USN_RECORD_V3 was parsed with V2 field offsets** (`primitives/windows_usn.py`).
  V3's `FileReferenceNumber` / `ParentFileReferenceNumber` are `FILE_ID_128`
  (16 bytes each), shifting every later field +16 bytes vs. V2 — but the V3
  branch reused the V2 offsets (and read `FileNameLength`/`FileNameOffset` from
  `0x56`/`0x58`, the V2 positions). On a real Windows 8+ V3 `$J` stream every
  record's FRN, parent FRN, USN, timestamp, reason and filename decoded wrong
  (silently). Fixed with a version-aware branch: V3 reads FRN@8(16B),
  PFRN@24(16B), Usn@40, TS@48, Reason@56, SourceInfo@60, SecurityId@64,
  FileAttributes@68, FileNameLength@72, FileNameOffset@74; V2 unchanged;
  other versions stop safely. Regression tests in `tests/test_usn_v3_offsets.py`
  anchor to the `winioctl.h` layout and fail under the buggy parser.
- **MFT `$FILE_NAME` `allocated` size was read at the wrong offset**
  (`primitives/windows_host.py`). `_parse_mft_record` read the allocated
  (allocated-length) field of the `$FILE_NAME` attribute at `cstart + 0x40`,
  which is the same offset as `name_length`, so it returned garbage bytes from
  the filename. The real NTFS `$FILE_NAME` layout is
  `parent@0, creation@8, mft_modified@16, accessed@24, allocated@0x28,
  real_size@0x30, flags@0x38, name_length@0x40, name@0x42`. Fixed to
  `cstart + 0x28`. The synthetic-fixture unit test never asserted `allocated`,
  which is exactly why the wrong offset was masked; `tests/test_windows_host.py`
  now locks it (`secret.txt` fixture uses size 1234 and asserts
  `fn.allocated == 1234`).
- **`windows.prefetch` used an entirely wrong offset model**
  (`primitives/windows_host.py`). The old parser treated the header as a sequence
  of indirection offsets (`name_off@0x0C`, `name_len@0x10`, `hash@0x14`,
  `metrics@0x1C`, `trace@0x24`, `run_count@0x98`, `last_run@0x9C`), but a real
  Windows Prefetch (SCCA) stores the executable name **inline** as UTF-16LE at
  `0x10` and the hash as a DWORD at `0x4C`; the version-dependent file-information
  block begins at `0x54` (68 bytes for v17) with section offsets/counts at
  `0x00/0x04/0x08/0x0C/0x10/0x14/0x18/0x1C` (metrics, metrics_count, trace,
  trace_count, filename_strings, filename_strings_size, volumes, volumes_count),
  and a version-keyed `last_run` / `run_count` position table. The old test passed
  only because its fixture encoded the same wrong model. Rewrote both the parser
  and the fixture (`tests/test_windows_host.py::_prefetch_file`) to the
  libscca / forensics.wiki layout and added the UTF-16 NUL terminator the inline
  name requires. Subtlety caught during verification: the inline name ends in a
  `NUL` byte, and with no explicit terminator the adjacent header padding formed a
  spurious `NUL NUL` pair one byte early, so slicing on `find(b"\x00\x00")` left an
  odd-length window and decoded a trailing `U+FFFD`. The parser now decodes the
  full 60-byte field through `_utf16` (which stops at the first `U+0000`) and is
  robust to both terminated and truncated buffers.

- **REGF `vk` (value key) offsets were wrong in BOTH `core/regf.py` and
  `core/hive.py`.** The value name was read at `0x10` instead of `0x14` (the 2-byte
  flags field at `0x10` was skipped), and small inline values (`< 5` bytes) were
  read from `0x0C` (the *type* field) instead of the `0x08` data dword. On a real
  hive this corrupted **every** value name (e.g. `Size` decoded as `\x00\x00Si`)
  and small `REG_DWORD`/`REG_BINARY` data (e.g. the dword `12345` decoded as
  `b'z\x00e\x00'`), while the unit fixtures passed because they encoded the same
  wrong `0x10` layout — a textbook circular-masking bug. Fixed both parsers to the
  canonical `CM_KEY_VALUE` layout (`name@0x14`, inline `data@0x08`,
  `data_len < 5` inline threshold, plus a `>= 0x80000000` big-data guard),
  cross-checked against `python-registry`'s `VKRecord`. The three vk fixtures
  (`tests/test_regf_offsets.py`, `tests/test_windows_amcache.py`,
  `tests/test_hive_deleted_keys.py`) now build spec-correct cells
  (`flags@0x10`, `name@0x14`) and assert the *old* `0x10` layout fails to parse.
  Empirical check: a spec-correct `vk` for `Size`/`12345` now round-trips
  (`name='Size'`, `data=b'\x39\x30\x00\x00'`), whereas an old-layout `vk` is now
  rejected (`name='ze'`, `data=b'\x00\x00\x00\x00'`) rather than silently agreed
  with — proving the fix removes the masking, not re-establishes it.

- **`windows.usb_artifacts` hard-errored when the SYSTEM hive lacked a `Select`
  key.** Control-set resolution did `int(hive.open('Select').value('Current').value())`
  inside `except (KeyError, ValueError, TypeError)`, but a *missing* `Select` key
  raises the library's `RegistryKeyNotFoundException` — which was not caught, so it
  escaped to the outer handler and turned the whole tool into `ERROR` instead of
  gracefully defaulting to `ControlSet001`. A forensic adapter should degrade, not
  abort. Added `RegistryModule.RegistryKeyNotFoundException` to that except so a
  missing/unreadable `Select` now falls back to `ControlSet001` (the common default)
  and continues. (Found by the first real test for this adapter — it previously had
  **zero** coverage.)

- **`windows.usb_artifacts` and `windows.evtx_summary` had no tests (zero
  coverage).** Both wrap external libs (`python-registry`, `python-evtx`) and returned
  results that were never verified. Added `tests/test_windows_usb_evtx.py` (5 tests)
  that drive the **real adapter code** against faithful fakes of the external APIs:
  the USB test pins control-set resolution, `Enum\USBSTOR` traversal, value extraction
  and `MountedDevices` UTF-16 decode (incl. undecodable-binary → `raw_hex`, never
  raises) and the missing-keys graceful-degradation path; the EVTX test feeds **genuine
  EVTX XML** (the real `http://schemas.microsoft.com/win/2004/08/events/event` schema)
  so its namespace parsing (`Provider@Name`, `EventID`, `TimeCreated@SystemTime`) is
  truly exercised, plus a malformed-record branch and the absent-lib `UNSUPPORTED`
  degradation. Note `python-evtx` is not installed in this environment, so the EVTX
  test injects a fake `Evtx` module; a real-evtx file remains the gold-standard follow-up.

Registry surface is now 99 tools (95 READ_ONLY, 4 STATEFUL); full suite 207 passed.

## 3.3.0 — Chain-of-custody audit ledger & robustness (2026-08-16)

New:

- Added an append-only chain-of-custody audit ledger (`dftk.core.audit.ToolAuditLog`). Every capability run can append one JSONL record carrying timestamp, tool, caller, resolved parameters (secret-looking keys masked, oversized strings truncated), safety level, network flag, status, summary, evidence SHA-256 hashes and errors. Enable it per invocation with `--audit PATH` on `dftk run`, `dftk recipe`, `dftk case run` and `dftk mcp`, or process-wide via the `DFTK_AUDIT_LOG` environment variable. The ledger is a side record: it never modifies evidence, and ledger serialization or I/O failures are swallowed so an examination is never interrupted by logging problems.
- Added a test-coverage gate. `pyproject.toml` now carries a `test` extra and `[tool.coverage]` configuration, and CI runs the suite under `--cov-fail-under=60` (current measured coverage is ~70%).
- Added a schema-driven no-crash regression test that invokes every registered capability with well-formed parameters derived from its own JSON schema and asserts the runner always returns an `Observation` instead of letting an exception escape.

Fixed:

- `file.strings` and `file.strings_unicode` no longer read the whole input into memory with `read_bytes()`; they now go through the bounded reader (4 GB default ceiling) and report `unsupported` on oversized input instead of risking exhaustion on multi-gigabyte evidence.
- MCP parameter validation no longer misclassifies opaque text as a filesystem path. Previously any string containing `/` or `\` was path-checked, which wrongly rejected values such as Windows registry keys (`HKLM\...`) and search patterns containing separators. Validation now applies to declared path parameters, explicit `./` / `../` relative paths, absolute paths, and values that actually resolve inside the evidence root.
- `CaseSession` run-sequence allocation is now serialized by an in-process lock in addition to the advisory file lock. The file lock covers cross-process callers (CLI plus MCP); the thread lock guarantees same-process thread serialization regardless of filesystem lock behaviour, resolving intermittent sequence races observed under load.
- `windows.*` FILETIME values are converted with integer arithmetic instead of float division, removing sub-microsecond drift on large 100-nanosecond values.
- `dftk prepare --rewrite-from` no longer rewrites arbitrary text files inside the toolkit. It now touches only launcher scripts (`.bat`/`.cmd`/`.ps1`) and backs up every file it changes under the DFTK-managed shim dir first, so the rewrite is reversible and never mangles data/config. Passing the toolkit's own location as `--rewrite-from` is now a no-op.
- `dftk mcp` no longer hardpins `mcp==2.0.0`; it accepts the validated 2.x line (`>=2.0.0,<3`) so a 2.0.1 SDK release does not break startup. The version string in the rejection message now reflects the actual DFTK release instead of a stale `3.1.0`.
- `dftk skill --install` no longer copies VCS/CI metadata (`.git`, `.gitignore`, `.github`) into the installed Agent skill directory.
- `archive.inventory` streams the archive central directory and stops after `limit` members instead of materializing the entire directory up front, so peak memory stays proportional to `limit` on very large archives (ZIP and TAR).
- The tool runner now distinguishes caller parameter errors from internal tool bugs: a `TypeError` raised while *binding* the call is reported as `Invalid parameters`, while a `TypeError` raised inside a tool body surfaces as `Tool execution failed` rather than being misreported as a caller mistake.
- The MCP server (`dftk mcp`) previously returned top-level `ok: true` for **every** capability run regardless of the underlying `observation.status`, so a client that branched on `ok` could mistake an `unsupported`/`error` run for success. The server now derives the top-level `ok` from `observation.status` (`ok` / `partial` → `true`; `unsupported` / `error` / `blocked` → `false`), and the gateway distinguishes a genuine worker crash (marked `error_type`) from a semantic failure (which carries a real `Observation` with `status` and `errors`). Client guidance was updated accordingly in the Skill.

## 3.2.1 — External tool discovery on POSIX

- Fixed external-tool discovery on POSIX hosts: launcher scripts (`.bat`/`.cmd`/`.ps1`) shipped in the toolkit bundle are now treated as runnable by presence alone instead of requiring the POSIX execute bit. `dftk prepare` plus `detect_external_tools` / `dftk doctor` now correctly locate these tools off-PATH on Linux/macOS CI hosts. Native binaries (`.exe`) and extensionless scripts still require the execute bit.

## 3.2.0 — External toolchain preparation

- Added `dftk prepare <toolkit_root>` to fold the win-tool-launcher environment-preparation workflow into DFTK: it records the extracted forensic-toolkit root and a DFTK-managed shim directory in `~/.dftk/toolchain.json`, generates two-layer launchers (`.bat` for Windows terminals, extensionless wrapper for the agent Bash) plus `set_path.bat`/`set_path.sh`, and optionally rewrites hardcoded roots inside the bundle (`--rewrite-from`).
- Extended the external-binary resolver (`core/external_tools`) to also search a single unified `$DFTK_TOOLS` root and the `dftk prepare` config (under `<root>`, `<root>/bin`, `<root>/<name>`, `<root>/<category>`, and the shim dir). Tools are now found on subsequent `dftk` calls without any manual PATH edit, even when the toolkit is on a non-PATH / non-readable drive.
- `detect_external_tools` / `dftk doctor` now report a `source` field (`PATH` / `DFTK_*_TOOL_DIRS` / `DFTK_TOOLS / dftk prepare root` / `dftk prepare shims`) and `doctor_report` carries a `toolchain` section with the active `toolkit_root` / `bin_dir`.
- Added public helpers `resolve_external_tool(name)` and `external_tool_source(name)` for tool bodies that need to invoke a discovered binary.

## 3.1.1 — Native Windows host-artifact tools and pcap enrichment

- Added native, dependency-free Windows host-artifact tools: `windows.mft` (NTFS $MFT path rebuild, SI/FN timestamps, flags, size), `windows.prefetch` (.pf v17/23/26/30 executable, hash, run count, last run, referenced files), `windows.lnk` (target, timestamps, TrackerDataBlock machine/MAC), `windows.recyclebin` (Recycle Bin $I original name, size, deletion time, paired $R).
- Enriched `network.capture_protocols` with DNS answer records (A/AAAA, CNAME) and HTTP responses (status, reason, Server).
- Moved the DFTK Agent Skill out of the pip package; `dftk skill --install` now fetches the standalone `DFTK-skill` repository at the matching version tag and installs the main skill plus standalone analysis skills.
- Tool count is now 72 (was 68).

## 3.1.0 — Native MCP and complete Agent Skill bundle

- Added native local stdio MCP as a thin adapter over the existing ToolRegistry, Observation and CaseSession interfaces.
- MCP exposes six meta-tools for health, capability discovery, describe, execution, case management and paged case-run reading; it does not implement an autonomous Agent loop.
- MCP defaults to READ_ONLY, network-off operation; root scope, network opt-in and STATEFUL ceiling are server-owner launch settings and are not model tool arguments.
- Capability execution is isolated in a worker process with a hard timeout so noisy parser stdout cannot corrupt stdio MCP framing.
- Case-scoped MCP execution is serialized to protect the existing CaseSession manifest read/sequence/write operation from concurrent requests.
- Added `dftk doctor` environment/capability diagnostics.
- `dftk skill --install` now installs the full progressive-disclosure DFTK Skill bundle (references/examples/templates), with Kimi/CodeBuddy targets added alongside existing targets.
- Added optional `mcp` dependency extra; base DFTK continues to have zero mandatory runtime dependencies.
- Public Python integration remains `get_registry()` / `run_tool()` with no breaking Observation/Evidence changes.

## 3.0.0 — Unified timeline & case correlation

- Added unified timeline correlation: `timeline.merge` normalizes and merges time-bearing events from multiple dftk tool outputs or inline sources into one source-attributed, sorted timeline.
- Added investigation case sessions via the `dftk case` CLI (and `dftk.core.case` API): `new`, `list`, `run`, `timeline`, and `export` (JSON/Markdown). A case accumulates read-only tool runs in an isolated `.dftk/cases/<id>/` workspace and correlates them into a single timeline without ever mutating evidence.
- Added `recipe.timeline.unified` composing a filesystem metadata timeline with optional extra Observation sources.
- Added Apache-2.0 copyright headers to all source and test files.
- Registry now exposes 68 tools (67 READ_ONLY, 1 STATEFUL) and 14 recipes.
- No breaking changes to the existing Observation/Evidence contract or the public Python API (`get_registry`, `run_tool`).

## 2.1.0 — Public release candidate

- Renamed the PyPI distribution from `digital-forensics-toolkit` to `dftk`.
- Kept the Python import package and CLI command as `dftk`.
- Added stable public Python entry points: `dftk.get_registry()` and `dftk.run_tool()`.
- Expanded the registered capability layer to artifact, Android, binary, database, network, Linux/server, Docker/web, Windows, E01, browser, email and crypto domains.
- Added explicit safety levels and separate network gating.
- Added agent-readable tool metadata including tags, produced evidence types, optional requirements, determinism and cost hints.
- Added PyPI/GitHub release automation scaffolding using Trusted Publishing.

The detailed technical changes from the internal 2.0/2.1 development cycle remain documented in `RELEASE_NOTES_2.1.md`.
