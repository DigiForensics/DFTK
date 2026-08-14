---
name: apk
description: >-
  Method-only playbook for static Android APK / APK-bundled native analysis:
  locating the launcher (main) activity and background-running capability from
  AndroidManifest, identifying native libraries loaded via System.loadLibrary,
  recovering hardcoded keys and crypto algorithms from the .so, and detecting
  encrypted secondary dex payloads (.ccb / packed payloads). Read-only posture
  — never install or execute the app. Teaches technique, not answers.
license: Apache-2.0
copyright: Copyright 2026 DyNooob @ DigiForensics
---

# APK (static, read-only)

Progressive-disclosure skill for analyzing an Android application package
(typically a `*.apk`) **without running it**. It covers the techniques behind
recurring finding classes:

1. **Entry point** — which Activity is the launcher (`MAIN` + `LAUNCHER`).
2. **Background-running capability** — whether the app can run/keep itself
   alive in the background (foreground-service permission, boot receiver,
   keep-alive service, wake lock).
3. **Native library** — which `.so` is loaded, and the key/value it exposes.
4. **Encrypted payload / asset** — which file the app decrypts at runtime, the
   algorithm, the key, and where the recovered secret is persisted.
5. **Obfuscation / packing** — encrypted secondary dex (`.ccb` and friends)
   unpacked by a native `decrypt()` at app init.

This skill is **method-only**. It contains no exam questions and no answer
values. Questions and their correct answers travel with the examination
material, not the shared skill.

## Hard rules

- **Never install or execute the APK on a device or emulator.** Static only:
  unzip, manifest parse, DEX decompile, native-library string/constant scan,
  entropy checks. Dynamic behavior (runtime decryption, unpacking) requires an
  isolated, snapshot-revertible VM or a sandbox trace — never the examiner
  machine.
- Preserve the original evidence immutable. Copy it to a working directory and
  analyze the copy.
- Distinguish **fact** (literal string in the `.so`, `loadLibrary` name,
  manifest declaration) from **inference** (what a native `decrypt()` likely
  does). When a value lives only inside an encrypted payload, mark it
  UNRESOLVED and state the escalation path.

## Reasoning contract

claim → evidence → capability → execution → verification

- **claim**: the specific question asked (e.g. "what is the launcher activity?").
- **evidence**: the exact artifact — manifest line, `loadLibrary` call site,
  literal string offset in the `.so`, tshark/http filter.
- **capability**: which tool produced it (jadx, unzip, strings scan, tshark).
- **execution**: the command run (keep it reproducible).
- **verification**: one of VERIFIED / SUPPORTED / CANDIDATE / UNRESOLVED /
  UNSUPPORTED.

## Verification levels

- **VERIFIED** — directly observed in the artifact (manifest line, literal
  string, `loadLibrary` name, filter result).
- **SUPPORTED** — strongly implied by multiple independent artifacts (e.g. DES
  functions + `DES_ede3_cbc_encrypt` present in the `.so` ⇒ DES used).
- **CANDIDATE** — one artifact points to it, needs corroboration.
- **UNRESOLVED** — value lives in an encrypted/secondary payload not
  recoverable statically; state the escalation (Ghidra/IDA on the `.so`, or
  isolated sandbox trace of the unpacking).
- **UNSUPPORTED** — contradicted by evidence; do not assert.

## Typical workflow

1. Copy the APK to a working dir; unzip to inspect `AndroidManifest.xml`,
   `lib/<abi>/*.so`, `assets/`, `classes.dex`.
2. Decompile DEX with `jadx` to read the manifest (as XML) and the Smali/Java
   sources. Use the manifest for entry point + permissions.
3. For native secrets: extract the `.so` named by `System.loadLibrary("…")`,
   string-scan it for keys and crypto constants (OpenSSL `DES_*`, `EVP_*`,
   `Java_<pkg>_...` JNI names).
4. Detect packing: look for `*.ccb` / encrypted assets and a native
   `decrypt(byte[], String)` called from `attachBaseContext` / `Application.onCreate`,
   followed by reflection-based `loadDex`. That is the protected secondary dex.
5. Report what is VERIFIED; for anything inside the encrypted payload, mark
   UNRESOLVED and give the escalation path.

## Relationship to sibling skills

- `dftk` — local file/archive/image forensics (no Android execution). Use its
  read-only tools when the evidence is a generic artifact.
- `server-forensics` — live server triage (uses 0 dftk tools).
- `reverse-exe` — generic executable reverse engineering (PE/ELF). APK native
  secrets overlap with it; use `reverse-exe` for the `.so` disassembly part.
- `pcap` — network capture analysis (the app's traffic lives there, not here).
- This skill uses 0 `dftk` tools and is not bundled in the `dftk` wheel.

## De-examification note

Distilled from a real suspected-malware APK case (loader Application that
unpacks `.ccb` secondary dex via a native `decrypt` in a custom `.so`, talks to
a backend over HTTP POST with a `sign` param). All question numbers and answer
values were stripped; only method remains. Keep exams' questions/answers with
the examination material.
