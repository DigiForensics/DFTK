# String & key recovery, and crypto-algorithm recognition

Goal: recover hardcoded secrets and name the algorithm family **from static
artifacts alone**.

## Plaintext key in the .so — Q "从库中加载的 key"

Many samples store a key as a literal C string inside the native library:
```
strings libxxx.so | grep -iE '^[A-Za-z0-9_!@#$%^&*()]{6,}$'
```
A high-entropy printable run that is *not* an OpenSSL/Android symbol is a
candidate key. Report its exact bytes and offset. Confirm by context: the string
often sits near `wb` (fopen mode), a path, or a `Java_..._getA` symbol.

If the app reads the key via `getA()` etc., and `getA` returns this literal,
the key is VERIFIED. If `getA` instead *computes* it (XOR / concat of fragments),
it is not a literal and is UNRESOLVED statically.

## Algorithm recognition — Q "解密算法"

Scan the `.so` for crypto library symbols:

| Family | Tell-tale symbols |
|--------|-------------------|
| AES    | `EVP_aes_128_ecb`, `AES_set_encrypt_key`, `private_AES_set_decrypt_key` |
| DES / 3DES | `DES_set_key_unchecked`, `DES_ede3_cbc_encrypt`, `DES_ecb3_encrypt` |
| RSA    | `RSA_private_decrypt`, `RSA_public_encrypt` |
| OpenSSL | `EVP_DecryptInit_ex`, `EVP_CIPHER_CTX_new` (generic; pair with the `EVP_aes_*`/`DES_*` above to name the algo) |

Report the algorithm **uppercase** (e.g. `DES`, `AES`, `3DES`, `RSA`). If both
`DES_ede3_*` and `EVP_aes_*` are present, prefer the one actually invoked by the
`decrypt` path; when ambiguous, report the family that the questions' context
points to and note the ambiguity.

## Key used to decrypt a file — Q "解密使用到的密钥"

If the decryption key is a plaintext literal in the `.so` or in the (decrypted)
secondary dex, report it VERIFIED. If it is derived at runtime (concatenation of
`getA()`..`getE()`, or decoded from an encrypted config), it is **not** a static
literal — mark UNRESOLVED and escalate (disassemble `getA`..`getE`, or sandbox
trace). Do **not** present a key fragment as the full key.

## Where the recovered secret is persisted — Q "配置文件名"

The app often writes a decrypted key into a config file: a `SharedPreferences`
XML (`getSharedPreferences("<name>", …)` ⇒ `<name>.xml` under
`shared_prefs/`), or a plain `File`/`getDir("<name>", …)`. Search the (decrypted)
dex for `getSharedPreferences(`, `new File(`, `getDir(` with the candidate name.
If only reachable inside the encrypted secondary dex, mark UNRESOLVED.

## Pitfalls

- A single `.so` links a whole OpenSSL build; the *presence* of `DES_*` does not
  prove the app's `decrypt` uses DES — but it is strong SUPPORTED evidence when
  no other cipher is invoked on that path.
- Never treat a crash/assertion string or a symbol name as a key. Keys are
  high-entropy *data*, not code symbols.
