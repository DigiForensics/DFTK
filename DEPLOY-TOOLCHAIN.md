# Deploying DFTK with an external forensic-toolkit bundle

This guide is for the **recipient** of a DFTK deployment: you were given the
DFTK GitHub link to install, and a separate compressed package of forensic
tools (IDA/Ghidra/jadx/apktool/tshark/…). It explains how to make those tools
discoverable to DFTK so they work in subsequent `dftk` calls — without editing
system PATH, without admin rights, and regardless of which drive you extracted
the package to.

The workflow is the `win-tool-launcher` environment-preparation step folded
directly into DFTK as `dftk prepare`.

## What you need

1. Python 3.10+ (no PyPI needed for DFTK core itself).
2. DFTK installed from the provided link:
   ```bash
   pip install "dftk[all]"      # or just: pip install dftk
   dftk doctor                  # sanity check
   ```
3. The forensic-toolkit zip, extracted somewhere writable (e.g. `E:\TOOLKIT`).
   Drive letter does **not** matter — `dftk prepare` derives the real location.

## Prepare the toolchain (the important step)

Point DFTK at the extracted directory:

```bash
dftk prepare E:\TOOLKIT
```

This:

- records the toolkit root + a DFTK-managed shim directory in
  `~/.dftk/toolchain.json` (always under your user home, so the agent can read
  it even when the toolkit is on an exotic / non-PATH drive);
- generates two-layer launchers in `~/.dftk/bin`:
  - `<tool>.bat` for real Windows `cmd` / PowerShell;
  - an extensionless `<tool>` wrapper for the agent Bash;
- writes `set_path.bat` / `set_path.sh` so the bare tool names also work in a
  plain terminal session.

Verify:

```bash
dftk doctor
```

The `external` section now lists each tool as `available: true` with a `source`
of `DFTK_TOOLS / dftk prepare root` (or `dftk prepare shims`). The `toolchain`
section shows the recorded `toolkit_root` and `bin_dir`.

### Call tools by bare name in a terminal (optional)

DFTK itself resolves tools via the config, so no PATH edit is required for
`dftk run`. If you also want to type `jadx` / `apktool` directly in a terminal
for the duration of that session, source the helper:

```text
Windows:  E:\TOOLKIT\..   (use the printed path)  %USERPROFILE%\.dftk\bin\set_path.bat
Bash:     . "$HOME/.dftk/bin/set_path.sh"
```

This is per-session only — it never modifies your persistent User PATH.

## Why this avoids the "tools not in a readable directory" problem

Previously, external tools had to be on PATH or under a `DFTK_<DOMAIN>_TOOL_DIRS`
env var that you set by hand. If the toolkit landed somewhere the agent sandbox
could not read, the tools were silently unusable.

`dftk prepare` fixes this by:

- writing its config under `~/.dftk/` (the user home — always readable by the
  agent);
- making DFTK's binary resolver search that config automatically on every call,
  in addition to PATH and the per-domain env vars.

So after one `dftk prepare`, the tools are found on all subsequent `dftk` calls
with no further configuration.

## Options

```bash
dftk prepare E:\TOOLKIT --bin-dir D:\cases\2026-001\.dftk\bin   # custom shim dir
dftk prepare E:\TOOLKIT --no-shims                              # only record the root
dftk prepare E:\TOOLKIT --rewrite-from D:\StaleKit             # fix hardcoded roots in launchers
dftk prepare --show                                            # print current toolchain config
```

- `--rewrite-from OLD_ROOT` rewrites a stale absolute path left inside the
  bundle's launcher scripts to the real toolkit root (mirrors the win-tool-launcher
  path-fix step). Off by default.
- `--bin-dir` is useful when you want the shims co-located with a specific case
  workspace instead of the user home.

## Fallbacks (locked / lab machines)

- **Cannot write User PATH / registry blocked:** not a problem — `dftk prepare`
  never needs them. Source `set_path.bat` / `set_path.sh` per session if you
  want bare-name access.
- **Only a portable JDK available (Ghidra/jadx need 21+):** bundle the JDK under
  the toolkit and let the tool's own launcher set `JAVA_HOME`; DFTK discovery is
  unaffected.
- **PyPI unreachable:** DFTK core has zero mandatory dependencies, so `pip install
  dftk` with no extras still works. Optional parsers (`[all]`) are best-effort.
- **Extracted onto exFAT / a USB stick:** prefer `dftk prepare` (config-based,
  no `+x` bit needed). Avoid relying on `+x` on a non-NTFS volume.

## How it wires into capability gating

A DFTK tool that depends on an external binary declares it via
`requires=("jadx",)`. At call time, if the binary is absent, `dftk_run` returns
`unsupported` with an explicit message naming the missing binary. After
`dftk prepare`, the same tool resolves the binary from the recorded toolkit root
and runs normally. No code change is needed per deployment.
