# Example — entry point & background capability (method only)

A worked *method* for "what is the launcher activity, and can it run in the
background?" Use placeholders; do not embed real answers.

## Steps

1. **Decompile the manifest**
   ```
   jadx -d out sample.apk
   # read out/resources/AndroidManifest.xml
   ```
2. **Launcher activity** — find the unique `<activity>` whose `<intent-filter>`
   contains both `android.intent.action.MAIN` and
   `android.intent.category.LAUNCHER`. Report its `android:name` as
   `<LAUNCHER_ACTIVITY>` (fully-qualified: `<PKG>.<Name>Activity`).
3. **Background capability** — grep the manifest for:
   - `android.permission.FOREGROUND_SERVICE`
   - a `<receiver>` with `android.intent.action.BOOT_COMPLETED`
   - a keep-alive / push `<service>` (`exported="true"`, `enabled="true"`)
   - `android.permission.WAKE_LOCK`
   If any of boot-receiver / foreground-service / keep-alive service is present,
   answer "有" (yes); else "无". Cite the specific lines.

## Claim cards (fill per case)

- claim: main entry activity = ?
  evidence: `AndroidManifest.xml` line `<N>` (`MAIN`+`LAUNCHER`)
  verification: VERIFIED
- claim: background-running permission = ?
  evidence: manifest lines `<N1,N2,…>` (FOREGROUND_SERVICE / BOOT_COMPLETED /
  KeepAliveService)
  verification: VERIFIED (or SUPPORTED if inferred from a push SDK)

## Notes

- A proxy `Application` that only unpacks a secondary dex does **not** change the
  launcher Activity answer — the launcher is still declared in the manifest.
- Keep the answer to the *declared* capability; do not assert runtime behavior
  from a permission alone.
