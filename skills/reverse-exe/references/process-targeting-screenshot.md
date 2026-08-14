# Process-targeting + screenshot capture

After injection, the malicious module may hunt a **specific process by name**
and capture its window.

## Find the screenshot target (process name)
1. In the injected module (or the loader's decrypted config), look for a second
   process-name string — distinct from the injection target.
2. APIs: `CreateToolhelp32Snapshot`/`Process32*` or `EnumProcesses` to enumerate,
   then compare against the hardcoded name to get its PID.
3. Resolve the window: `EnumWindows` / `FindWindow` /
   `GetWindowThreadProcessId`, walking until the window belongs to that PID.

## Find the capture routine
- `GetDC`/`GetWindowDC`/`GetWindowRect` → `BitBlt` or `PrintWindow` (or
  `DwmThumbnail`) to copy the window/client area into a compatible bitmap.
- The bitmap bits (`GetDIBits` / `BitBlt` into memory DC) become the screenshot
  buffer.

## Find where it is saved
- The screenshot buffer is then **encrypted and written to disk**
  (`CreateFile`/`WriteFile`, often under `%TEMP%` or a dropped folder).
- The encryption uses a **separate key** from the module-decrypt key — see
  `screenshot-encryption-key.md`.

## Verification
- **VERIFIED** if the target process name + capture API are observed (static or
  sandbox).
- **SUPPORTED** if capture APIs are present and the name is inferred.
- **UNRESOLVED** if the name is encrypted and not yet decoded.

## Distinction
- Injection target = where code runs (e.g., `<TARGET_PROCESS>`).
- Screenshot target = which window gets captured (e.g., `<SHOT_TARGET>`).
They are different processes; answer each independently.
