# Example — recovering an in-memory encrypted module (method only)

> No exam answers. Illustrates the static-decrypt workflow using placeholders.

## When this applies
Section entropy shows a big ciphertext blob, and the injection path writes a
buffer that was just decrypted in-process. You want the module out as a PE.

## Workflow
1. **Locate ciphertext**: high-entropy `.data`/resource blob with no `MZ` header.
   Note its file offset and length.
2. **Locate decrypt**: the API just before `WriteProcessMemory` that produces
   the written buffer. Identify key + IV sources (`lea` to constants or decoded
   config).
3. **Identify algorithm**: from `crypto-identification.md` (`AES` with IV ⇒ CBC
   is typical). Record mode/key-size if visible (`EVP_aes_256_cbc` ⇒ AES-256-CBC).
4. **Obtain key/IV**:
   - plaintext constant ⇒ read bytes directly, or
   - runtime-decoded ⇒ replicate the StringDecoder (needs a real disassembler or
     sandbox; see `obfuscation-and-sandbox.md`).
5. **Decrypt** with the identified algorithm/mode/key/IV (e.g., PyCryptodome
   `AES.new(key, AES.MODE_CBC, iv).decrypt(ct)`).
6. **Validate**: output starts with `MZ` and parses as a PE (`pefile` opens it
   without error). If it does, the key/IV/algorithm are **VERIFIED**.

## If decryption fails
- Wrong key ⇒ re-trace the key source (maybe it is decoded, not constant).
- Wrong mode ⇒ CBC vs CTR vs CFB; the IV presence implies a chaining mode, but
  confirm via the `EVP_CipherInit` cipher argument if reachable.
- Wrong blob bounds ⇒ re-measure the ciphertext length (must be a multiple of
  the block size for CBC).

## Safety
Perform decryption on the **copy**, off the host's trusted environment. Never
execute the recovered module.
