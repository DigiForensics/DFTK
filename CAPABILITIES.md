# Capability map — DFTK 3.7.0

The registry contains 136 tools (131 READ_ONLY, 5 STATEFUL): 121 primitives and
15 recipes across 29 domains. This is a map of supported operations, not proof
that every optional dependency is installed or every input variant is supported.

## Discover exact contracts

```bash
dftk list --group
dftk suggest /evidence/acquisition/sample.bin
dftk suggest tls_sni --direction produce
dftk describe media.ocr_batch
dftk doctor
```

[The static manifest](docs/capabilities.json) contains every name, parameter,
path role and requirement. The companion [generated capability catalog](https://github.com/DigiForensics/DFTK-skill/blob/main/references/capabilities.md)
renders those contracts for Agents. Counts use capability names, not the eight
meta-tools exposed by the [MCP adapter](docs/mcp.md).

## Domains

| Domain | Tools | Supported operations |
|---|---:|---|
| `android` | 7 | APK/DEX, manifest, endpoints, app-data and preferences |
| `application` | 2 | Declared application profiles and normalized records |
| `archive` | 2 | ZIP/TAR inventory and controlled extraction |
| `artifact` | 1 | Signature/container identification and hashes |
| `binary` | 12 | PE/ELF/Mach-O inventory, deep structures and byte comparison |
| `browser` | 8 | Chromium/Firefox history, downloads, bookmarks, cookies and search terms |
| `case` | 2 | HTML reporting and audit/result verification |
| `correlation` | 1 | Source-linked entity graph |
| `crypto` | 4 | BIP39, entropy and one-candidate OpenSSL decryption |
| `custody` | 1 | Audit ledger verification |
| `database` | 10 | SQLite queries/search, pages/freelist/WAL/recovery and SQL dump inventory |
| `docker` | 2 | Offline container inventory and JSON-file logs |
| `email` | 4 | MIME/authentication metadata, DKIM and SPF |
| `encoding` | 1 | Bounded decoding candidates |
| `evidence` | 2 | Intake manifest and paged directory metadata |
| `file` | 5 | Hashes, ASCII/Unicode strings, search and text windows |
| `filesystem` | 6 | Read/stat/list/walk/deleted entries and workspace extraction |
| `image` | 3 | Disk partitions, EWF metadata and E01 filesystem inventory |
| `linux` | 4 | Offline accounts/packages, authentication and persistence candidates |
| `malware` | 1 | Bounded YARA matching |
| `media` | 5 | Metadata, authorised previews/contact sheets and single/batch OCR |
| `memory` | 6 | Six fixed Volatility 3 plugin adapters |
| `network` | 8 | Capture inventory, flows, TCP reassembly, HTTP, DNS and TLS |
| `recipe` | 15 | Optional bounded compositions, including guided intake and unified timeline |
| `server` | 2 | Network-gated fixed SSH inventory/snapshot profiles |
| `timeline` | 3 | File metadata, normalized merging and ordered event-chain hunting |
| `tree` | 1 | Bounded source-tree inventory |
| `web` | 4 | Web-root/config inventory, access logs and WebShell leads |
| `windows` | 14 | Registry/EVTX, MFT/USN, Prefetch/LNK/Recycle Bin, Amcache/Shimcache/SRUM |

## Source preservation and derived work

READ_ONLY capabilities examine evidence or derive in-memory facts. Five tools
write derived workspace output: `archive.extract_safe`, `crypto.openssl_decrypt`,
`filesystem.extract`, `network.http_sessions`, `case.report_html`. They require
STATEFUL permission. Cases/audit may persist results independently of that
capability classification. There are no DESTRUCTIVE registry tools.

Case-registered output paths/hashes allow follow-up parsing inside the workspace
without copying files into acquired evidence. Use the same Case. Unregistered or
modified workspace inputs remain blocked by root-aware evidence-input policy.

## Important scope distinctions

- Media metadata/discovery are not visual review. Native previews/contact sheets
  require scoped consent and model image support. Video samples omit audio and
  unsampled frames. GPU-first local OCR is separate; CPU requires affirmative
  consent. See [media contracts](docs/media-perception.md).
- SQLite readers use immutable main-database views and warn about sidecars.
  Byte-level recovery distinguishes bounded committed reconstruction from heuristic
  deleted candidates; unsupported roots and limits remain explicit.
- Archive inventory exposes encryption hints, not passwords. Supplied-password ZIP
  extraction and one-candidate OpenSSL decryption do not guess. ZIP plaintext
  validation checks the central directory rather than member CRC/content. Some
  encrypted ZIP methods and RAR/7z extraction remain unsupported.
- Native FAT/raw filesystem operations are distinct from optional EWF/TSK access.
  The required engine and supported filesystem determine what can actually be read.
- `memory.*` wraps six fixed Volatility operations. DFTK does not implement its own
  memory engine, Plaso super-timeline builder or arbitrary plugin/shell execution.
- Browser records, Shimcache entries, static endpoints, YARA hits and graph joins
  require interpretation; they do not alone prove execution, attribution or exfiltration.
- DKIM/SPF and fixed SSH collection require explicit network opt-in. Discovering
  an external binary does not create adapters for all its functionality.

## Cases, verification and reporting

CLI Cases provide artifact memory/dispositions, attempts, brief/coverage,
graph/timeline views, cited findings and JSON/Markdown export. MCP offers the
documented subset through `dftk_case` plus result paging; finding registration is
available through CLI/Python. `case.report_html` is a STATEFUL capability.

The default Case location is `$DFTK_WORKSPACE` or `~/.dftk`, with records under
`cases/<id>/`. Source hashes, derivation graphs, stored-result checks and audit
seals support integrity review; they do not certify acquisition completeness or
semantic truth. See [user guide](docs/user-guide.md), [safety](SAFETY.md),
[architecture](ARCHITECTURE.md) and [validation](docs/agent-reliability.md).
