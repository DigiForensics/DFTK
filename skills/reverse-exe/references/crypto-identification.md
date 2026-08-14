# Crypto identification — which algorithm decrypts the payload?

Report the algorithm name in **uppercase** (e.g., `AES`, `RC4`, `DES`, `TEA`,
`XOR`).

## Signature constants (static)
- **AES**: `AES_set_encrypt_key`, `AES_set_decrypt_key`, `AES_cbc_encrypt`,
  `EVP_CipherInit`/`EVP_DecryptInit` with `EVP_aes_256_cbc` etc.; S-box `0x63`,
  `0x11B` polynomial, `MixColumns` constants `0x09/0x0B/0x0D/0x0E`.
- **RC4**: `RC4_set_key`, `RC4()` call, 256-byte S-box init (`KSA`/`PRGA`),
  `0x100`-entry lookup.
- **DES/3DES**: PC-1/PC-2 permutation tables, `0x…` key-schedule constants.
- **TEA/XTEA**: magic `0x9E3779B9`, 32-round structure, `0xC6EF3720` (XTEA).
- **XOR**: repeating-key `xor` loop; ciphertext often shows a periodic pattern.

## The OpenSSL `EVP` assertion trick
Statically-linked OpenSSL leaves assertion strings in the binary, e.g.:
`assertion failed: (AES_ENCRYPT == enc) || (AES_DECRYPT == enc)` and
`assertion failed: in && out && key && ivec`. The `ivec` (IV) token is the
tell that **an IV is used ⇒ a chaining mode (CBC/CFB/OFB/CTR), not ECB**.
Presence of `AES_BLOCK_SIZE` + `EVP_CIPHER_iv_length(...) <= 16` ⇒ block cipher
with a 16-byte IV ⇒ **AES-CBC** is the common case.

## Reporting
- Name only, uppercase: `AES`, `RC4`, `DES`, `TEA`, `XOR`.
- If you can also determine the mode/key-size from `EVP_aes_256_cbc` etc., note
  it as supporting detail — but the asked value is the algorithm name.

## Verification
- **VERIFIED** if the cipher routine/symbol is directly identified.
- **SUPPORTED** if only library assertion/constant strings point to it.
- **CANDIDATE** if multiple ciphers are linked and the exact one is ambiguous.
