# Static recon — first pass on a suspicious executable

Goal: build a fact base without executing the sample.

## 1. Hash and store the original
- `certutil -hashfile sample.exe SHA256` (or `sha256sum`).
- Copy to a working dir; **analyze the copy**, never the original.
- Record size, compile timestamp, and any embedded digital-signature.

## 2. Section map + entropy
Use `pefile` to list sections with `VirtualAddress`, `SizeOfRawData`, and
compute Shannon entropy per section.
- **High entropy (~6–8) on `.data`/`.rdata`** ⇒ encrypted or compressed
  payload (the in-memory module is often stored here as ciphertext).
- Low-entropy code sections with a few `0xCC` pads ⇒ debug build (richer
  metadata, sometimes source paths like `minkernel\crts\...\cpp`).

## 3. Embedded resources / decoy documents
Samples often bundle a benign file to look legit (e.g., a Word/OOXML doc with a
`PK\x03\x04` ZIP header: `[Content_Types].xml`, `word/document.xml`).
- Extract such ZIPs (`zipfile`) and read the XML — but treat them as **decoys**
  unless config strings actually appear inside. A decoy doc rarely holds the
  real key.
- Resource types of interest: RT_RCDATA / custom blobs that are not icons/manifests.

## 4. Import triage
Read `DIRECTORY_ENTRY_IMPORT`. Flag the behavior classes:
- **Injection**: `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`,
  `SetWindowsHookEx`, `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`,
  `CreateToolhelp32Snapshot`+`Process32*`.
- **Screenshot**: `FindWindow`, `EnumWindows`, `GetWindowThreadProcessId`,
  `BitBlt`, `PrintWindow`, `GetDC`/`GetWindowDC`, `DwmThumbnail`.
- **Evasion**: process-name lists of analyst tools (`x64dbg`, `ida`, `procmon`,
  `wireshark`, …) — a strong signal of injection + anti-analysis.
- **Crypto**: `advapi0`/`Crypt*` (OS crypto) OR **no crypto imports at all**
  despite encryption behavior ⇒ crypto is **statically linked** (see below).

## 5. Spot statically-linked crypto
If imports show no `Crypt*` but the binary is large with many
`crypto\...\*.c`-style paths and symbols like `AES_set_encrypt_key`,
`EVP_CipherInit`, `AES_BLOCK_SIZE`, `RC4_set_key`, then OpenSSL (or similar) is
**statically linked**. The real cipher calls live in `.text`, not in the IAT —
plan to find them by string/constant, not by import name.

## Output
A one-page recon card: hashes, entropy hotspots, import behavior classes, and
"statically-linked crypto? Y/N". Feed it into the next references.
