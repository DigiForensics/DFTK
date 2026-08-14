# In-memory encrypted payload — the injected module

The injected module is often stored **as ciphertext** in the sample's memory
(or in a high-entropy section/resource) and decrypted just before injection.

## Locate the ciphertext
- High-entropy region in `.data`/`.rdata`/resource (from `static-recon.md`).
- A large blob with no readable PE header (`MZ`/`PE`) but decryptable to one.

## Locate the decrypt call
Trace the injection path (`WriteProcessMemory` / `NtWriteVirtualMemory` /
`VirtualAllocEx`). The bytes written usually come from a buffer that was just
decrypted in-process. The decrypt routine:
- takes a key + (often) an IV,
- emits a `MZ…PE` image,
- hands it to the injection API.

## Why static key recovery can fail
The key and IV may be:
- **plaintext constants** (easy: read them, then AES/RC4-decrypt the blob), or
- **decoded at runtime** from an encrypted config blob via a custom routine
  (hard: the bytes are not in the file).

If the key is runtime-decoded, you cannot recover the module by static means
alone. Recognize this early (see `key-extraction.md`) and pivot to
`obfuscation-and-sandbox.md`.

## Verification
- **VERIFIED** if you decrypt the blob and obtain a valid PE (or observe it in
  a sandbox).
- **SUPPORTED** if the decrypt call + ciphertext are clear but you lack the key.
- **UNRESOLVED** if the payload location/key are both runtime-only.

## Safety
Never run the sample to "just see" the decrypted module. Either decrypt
statically or observe it in an isolated, snapshot-able VM.
