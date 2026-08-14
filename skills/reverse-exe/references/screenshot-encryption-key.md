# Screenshot encryption key

The screenshot buffer is re-encrypted before being written to disk. Its key is
usually **distinct** from the module-decrypt key.

## How it typically appears
- A fixed **pointer to a buffer**, e.g. `0x11AABB22` (example format). The value
  may be a `0x…` immediate that is the **address** of a DWORD/byte buffer
  holding the key, not the key bytes themselves — read the bytes at that
  address.
- A second hardcoded string/byte array alongside the module key.
- Sometimes the same stream cipher (RC4) seeded differently, or a separate AES
  key/IV.

## Recovery steps
1. Locate the `WriteFile` of the encrypted screenshot. Trace its buffer back to
   the encrypt call.
2. The encrypt call's key argument is the screenshot key. If it is a `0x…`
   immediate, dereference it (VA − ImageBase → file offset) to read the actual
   key bytes.
3. If the key is runtime-decoded (common), recover it via the config decoder
   (see `key-extraction.md` + `obfuscation-and-sandbox.md`).

## Reporting format
- If asked for a `0x…` value, give the **address/pointer** exactly as it
  appears, or the key bytes if that is what is requested. Match the question's
  expected format precisely.

## Verification
- **VERIFIED** if used to successfully decrypt a recovered screenshot.
- **SUPPORTED** if read as a constant near the screenshot-encrypt call.
- **UNRESOLVED** if runtime-decoded and not yet recovered.
