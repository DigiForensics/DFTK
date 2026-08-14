# Key extraction — recovering the decryption key

The key may be easy (plaintext) or hard (runtime-decoded). Triangulate first.

## Case A — plaintext key
- A `lea reg, [addr]` near the decrypt call points at a byte array / string
  literal. Dump that address (file offset = VA − ImageBase mapped through the
  section). The key is the bytes there.
- AES: 16 / 24 / 32 bytes for AES-128/192/256. RC4: any length. XOR: the
  repeating key.
- If the sample references `EVP_BytesToKey` with a password string, that string
  is the effective key material.

## Case B — runtime-decoded key (the hard case)
If the key buffer is zero-initialized in the file and filled via a call, the
key comes from an **encrypted config blob** decoded by a custom routine:
1. Find the function that fills the key buffer (a `lea edx,[keybuf]` followed by
   a `call`). That callee copies/decodes the key from a source pointer.
2. Find the **StringDecoder / config decode** routine. It is usually reached
   through an **import thunk** (see `obfuscation-and-sandbox.md`), so static
   xref may only show `jmp [IAT_entry]`. Resolve the real target in a
   disassembler.
3. Replicate the decode (XOR / RC4 / custom) on the config blob to recover the
   key string/bytes.

## Why a naive XOR brute-force often fails
A 1–2 byte XOR brute-force over ciphertext-looking strings typically yields only
**spurious** hits (fragments like `iv`/`Key` inside garbage). Real samples use
longer/derived keys or stream ciphers (RC4). Don't over-trust a "decoded"
string unless it is clean, meaningful ASCII.

## Verification
- **VERIFIED** key used in a successful decryption (module or config decodes to
  valid data).
- **SUPPORTED** key read as a constant; not yet proven by decryption.
- **UNRESOLVED** key is runtime-decoded and not yet recovered.

## Safety
Keep keys in your private working notes / claim card — they are case evidence,
not something to publish in a shared skill.
