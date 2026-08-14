# Obfuscation & sandbox — when static hits a wall

Some samples defeat pure static analysis. Recognize the signals and pivot.

## Signal 1 — custom import / thunk table
The binary calls through `jmp dword ptr [table]` stubs where `table` is **not**
the normal `.idata` IAT (pefile cannot map it to an imported function). This is
a **loader-resolved** import table: the real targets are filled at runtime.
- Consequence: xrefs stop at `jmp [addr]`; you cannot statically name the callee.
- Fix: open the sample in **IDA Pro / Ghidra**, let the loader resolve imports,
  then follow the thunk to the real function.

## Signal 2 — encrypted/config strings
Strings that look like `3L$4…3L$h…` (period-3-ish garbage) or random symbol
mixes are **ciphertext** for a custom string decoder. A 1–2 byte XOR brute-force
will mostly produce false positives — don't trust it.
- Fix: locate the StringDecoder routine (via the resolved import in a real
  disassembler) and replicate its transform on the config blobs.

## Signal 3 — high-entropy payload, no plaintext key
The module and its keys are all runtime-derived. Static recovery is impractical.

## The sandbox pivot (never on the host)
1. Snapshot a clean VM. Copy the sample in. **Do not** run it on your analysis
   host.
2. Run an **API Monitor / Rohitab** trace and **Process Monitor** capture.
3. Observe, in order: `CreateRemoteThread` target, the decrypt call's key/IV
   arguments, `FindWindow`/`EnumWindows` target, `BitBlt`/`PrintWindow` capture,
   and the `WriteFile` of the encrypted screenshot (note its encrypt key arg).
4. Record the observed key/process values as **VERIFIED** evidence.

## Decision rule
If you cannot name a callee or read a config string after triage + capstone,
stop forcing static analysis and move to IDA/Ghidra or a sandbox trace. The
host-execution shortcut is never acceptable.
