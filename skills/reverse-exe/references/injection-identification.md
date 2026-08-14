# Injection identification — which process is the target?

The sample injects a malicious module into another process. Determine the
**target process name**.

## Static path (preferred)
1. Find the injection API: `CreateRemoteThread` / `NtCreateThreadEx` /
   `QueueUserAPC` / `SetWindowsHookEx`. The `hProcess` argument comes from
   `OpenProcess`.
2. Trace backwards from `OpenProcess` to where the process handle is chosen:
   - Often `CreateToolhelp32Snapshot` → `Process32First/Next` loop comparing
     each `szExeFile` against a **hardcoded process-name string**, or
   - a direct `OpenProcess` on a hardcoded name.
3. The compared/name string is your **target process**. It is frequently
   plaintext in the binary (e.g., `<TARGET_PROCESS>` such as a common editor or
   browser). If it is *not* plaintext, the name is in the encrypted config —
   see `key-extraction.md` and `obfuscation-and-sandbox.md`.

## Quick signal: the anti-analysis list
Many injectors enumerate a hardcoded list of analyst tools
(`x64dbg`, `x32dbg`, `ollydbg`, `ida`, `ida64`, `procexp`, `procmon`,
`wireshark`, `tcpview`, `ghidra`, `dnspy`, `apimonitor-*`) and exit/stall if
found. This list is usually plaintext and sits near the injection code — a
reliable landmark for locating the injection function.

## Verification
- **VERIFIED** if you see the literal target name compared in the
  `Process32*` loop, or `OpenProcess("name")`.
- **SUPPORTED** if only the injection API chain is present and the name is
  inferred.
- **CANDIDATE/UNRESOLVED** if the name is encrypted and not yet decoded.

## Note
The injection target (where code runs) is **distinct** from the screenshot
target (see `process-targeting-screenshot.md`). Do not conflate them.
