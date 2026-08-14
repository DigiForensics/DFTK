# Tooling for APK static analysis

All read-only. Nothing here installs or runs the app.

## Unpack / inspect

- `unzip -l sample.apk` — list entries without extracting.
- Python `zipfile` — surgical extraction of `lib/*`, `assets/*`, `classes.dex`,
  `AndroidManifest.xml`.

## DEX decompile (manifest + sources)

- **jadx** — `jadx -d out sample.apk`. Produces `resources/AndroidManifest.xml`
  (readable) and `sources/` (Smali→Java). Best all-rounder.
- **apktool** — `apktool d sample.apk`. Decodes binary XML and resources
  faithfully; pair with `jadx` for code.
- **androguard** (Python) — scriptable: `a, d, dx = AnalyzeAPK("sample.apk")`;
  read `a.get_activities()`, `a.get_permissions()`, `a.get_services()` directly.
  Use when you want to grep programmatically across many samples.

## Native library

- `strings` / Python `re.findall(rb'[\x20-\x7e]{4,}', data)` — literals & keys.
- `grep Java_` — JNI symbol surface.
- For disassembly of the `.so`: `reverse-exe` skill + Ghidra/IDA (out of scope
  for static string recovery; escalate there).

## Crypto sanity check (offline)

- `pycryptodome` — only to *replicate* a decryption once you have the key/mode
  from the `.so` (e.g. to confirm a `.ccb` decodes to a `dex` magic). Never to
  brute-force; 8/16/24-byte keyspace is infeasible.

## Evidence hygiene

- Keep the original APK immutable; analyze a copy in a working directory.
- Record the SHA-256 of the APK and of each extracted `.so` you rely on.
- Save the exact `jadx`/`apktool` version used — decompiler output drifts.
