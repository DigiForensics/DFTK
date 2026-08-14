# Example — injection + AES module + screenshot (method only)

> Synthetic scenario. Replace `<…>` with the values from your own sample.
> This file contains **no exam answers**.

## Setup
- Sample: `sample.exe` (suspicious, double-extension `.doc.exe` disguise).
- Posture: static only; copy to working dir; `sha256` recorded.

## Step 1 — recon
- `pefile`: imports include `CreateRemoteThread`, `OpenProcess`,
  `VirtualAllocEx`, `WriteProcessMemory`, `CreateToolhelp32Snapshot`.
- Anti-analysis list present: `x64dbg`, `ida`, `procmon`, `wireshark`, …
- A large `.data` section has entropy ~6.2 ⇒ encrypted payload likely there.
- `strings` shows `aes_key` and OpenSSL `EVP`/`AES_*` assertion strings ⇒
  statically-linked OpenSSL, AES family.

## Step 2 — injection target (`<TARGET_PROCESS>`)
- Disassemble the function referencing `CreateRemoteThread`.
- Backtrack `OpenProcess` → `Process32*` loop comparing `szExeFile` to a
  hardcoded string `<TARGET_PROCESS>`.
- Claim: sample injects into `<TARGET_PROCESS>`. Level: **VERIFIED** (literal
  name compared).

## Step 3 — payload algorithm (`<ALGORITHM>`)
- The decrypt routine's symbols/`EVP_aes_*_cbc` + the `in && out && key && ivec`
  assertion ⇒ `<ALGORITHM>` with an IV ⇒ CBC.
- Claim: module decrypted with `<ALGORITHM>`. Level: **VERIFIED**.

## Step 4 — module key (`<MODULE_KEY>`)
- `lea edx,[keybuf]` near the decrypt call; the callee fills it from a config
  blob. If the blob is runtime-decoded, recover via the StringDecoder
  (see `obfuscation-and-sandbox.md`).
- Claim: module key = `<MODULE_KEY>`. Level: **VERIFIED** (used to decrypt a
  valid PE) or **UNRESOLVED** (runtime-only).

## Step 5 — screenshot target (`<SHOT_TARGET>`)
- In the decrypted module, find a second process-name string + `EnumWindows`/
  `FindWindow` + `GetWindowThreadProcessId`.
- Claim: screenshots `<SHOT_TARGET>`'s window. Level: **VERIFIED**/**SUPPORTED**.

## Step 6 — screenshot key (`<SHOT_KEY>`)
- `WriteFile` of the encrypted screenshot → encrypt call key arg. A `0x…`
  immediate is usually the **address** of the key buffer; dereference it.
- Claim: screenshot encrypted with `<SHOT_KEY>`. Level: **VERIFIED**/**UNRESOLVED**.

## Takeaway
The same chain (inject → AES-decrypt module → enumerate+screenshot → re-encrypt
to disk) repeats across many samples; only the five `<…>` values differ. Recover
them with the references; never hardcode answers into a shared skill.
