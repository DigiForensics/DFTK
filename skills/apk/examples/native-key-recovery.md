# Example — native key & algorithm recovery (method only)

A worked *method* for "which `.so` is loaded, what key does it expose, and what
algorithm decrypts the payload?" Use placeholders; do not embed real answers.

## Steps

1. **Locate the library**
   ```
   grep -rn 'System.loadLibrary(' out/sources
   ```
   Argument `<BASE>` ⇒ library file `lib/lib<abi>/lib<BASE>.so`.

2. **Extract the `.so`** from the APK (see `tooling.md`) and string-scan it.

3. **Find the key literal** (Q "从库中加载的 key")
   ```
   strings lib<BASE>.so | grep -iE '^[A-Za-z0-9_!@#$%^&*()]{6,}$'
   ```
   A high-entropy run near `Java_..._getA` / an `fopen "wb"` is the candidate
   key `<LIB_KEY>`. Report exact bytes + offset.

4. **Name the algorithm** (Q "解密算法")
   ```
   strings lib<BASE>.so | grep -E 'DES_|EVP_aes|AES_set_encrypt_key|RSA_'
   ```
   Map symbols → algorithm (see `string-and-key-recovery.md`). Report uppercase
   `<ALGORITHM>` (e.g. `DES`, `AES`).

5. **Find the decrypted payload** (Q "解密的文件的名称")
   In the decompiled `Application`, locate `decrypt(bytes, path)` and the file
   extension it operates on (`*.ccb`, an `assets/<FILE>` reference, etc.). Report
   `<DECRYPTED_FILE>`. If the name only appears inside the encrypted secondary
   dex, mark UNRESOLVED and escalate (Ghidra/IDA on `decrypt`, or sandbox trace).

6. **Decryption key & config file** (Q "密钥" / Q "配置文件名")
   If `<DECRYPT_KEY>` and `<CONFIG_FILE>` are plaintext literals (in the `.so` or
   the decrypted dex), report VERIFIED. If computed at runtime, mark UNRESOLVED.

## Claim cards

- claim: loaded library = ?  evidence: `System.loadLibrary("<BASE>")` @ <file>:<line>  VERIFIED
- claim: key from library = ?  evidence: literal `<LIB_KEY>` @ so offset <off>  VERIFIED
- claim: algorithm = ?  evidence: `DES_ede3_cbc_encrypt` / `EVP_aes_*` in `.so`  SUPPORTED
- claim: decrypted file = ?  evidence: `decrypt(bytes, "<DECRYPTED_FILE>")` @ <line>  VERIFIED/UNRESOLVED
- claim: decryption key = ?  evidence: literal / computed  VERIFIED/UNRESOLVED
- claim: config file = ?  evidence: `getSharedPreferences("<CONFIG_FILE>")`  VERIFIED/UNRESOLVED

## Escalation note

When steps 5–6 are UNRESOLVED, the values live in the encrypted secondary dex.
State: "reverse the `.so` `decrypt` JNI in Ghidra/IDA to get key+mode, replicate
with pycryptodome to unpack the `.ccb`, then decompile." Do not guess.
