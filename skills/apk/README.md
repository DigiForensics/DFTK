# apk (skill)

Method-only playbook for **static** Android APK / APK-bundled native analysis:
launcher-activity & background-running capability from the manifest, native
library identification (`System.loadLibrary`), key/algorithm recovery from the
`.so`, and detection of encrypted secondary dex (`.ccb`) payloads.

**Read-only posture:** never install or execute the app. Unzip, manifest-parse,
DEX-decompile, native-library string/constant scan, entropy checks. Dynamic
unpacking requires an isolated, snapshot-able VM or a sandbox trace.

## What it is / isn't

- It is a *technique* skill. It contains **no exam questions and no answer
  values**.
- It complements `dftk` (local artifact forensics), `server-forensics` (live
  server), `reverse-exe` (generic executable RE — use it for the `.so`
  disassembly), and `pcap` (the app's network traffic). It uses 0 `dftk` tools
  and is not bundled in the `dftk` wheel.

## Layout

```
apk/
  SKILL.md                        # entry + reasoning contract + hard rules
  references/                      # load on demand
    manifest-entrypoints.md
    native-libraries.md
    encrypted-secondary-dex.md
    string-and-key-recovery.md
    tooling.md
  examples/                        # method-only walkthroughs (no answers)
    entry-and-permissions.md
    native-key-recovery.md
  templates/                       # claim-card.md, case-report.md
  README.md  CHANGELOG.md  LICENSE
```

## Install (copy the directory)

This skill lives inside the DFTK repository at `skills/apk/` (alongside
`skills/dftk`). It is **not** published to PyPI and not auto-installed by
`dftk`. To use it as a standalone skill, copy the directory:

```bash
git clone https://github.com/DigiForensics/DFTK
cp -r DFTK/skills/apk ~/.workbuddy/skills/apk
```

## Reasoning contract

claim → evidence → capability → execution → verification, with levels VERIFIED /
SUPPORTED / CANDIDATE / UNRESOLVED / UNSUPPORTED (shared with `dftk`,
`server-forensics`, `reverse-exe`, `pcap`).

## De-examification

Distilled from a real suspected-malware APK (proxy `Application` unpacking `.ccb`
secondary dex via a native `decrypt` in a custom `.so`, HTTP-POST backend with a
`sign` param). All question numbers and answer values were stripped; only method
remains. Keep exams' questions/answers with the examination material.
