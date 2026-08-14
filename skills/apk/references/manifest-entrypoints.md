# Manifest: entry point & background-running capability

The `AndroidManifest.xml` is the single source of truth for **what the app
declares**. jadx renders it as readable XML under `resources/AndroidManifest.xml`;
`apktool d` produces the original binary-XML decode.

## Launcher (main) activity — Q "主入口"

- The launcher Activity carries the intent-filter:
  ```xml
  <intent-filter>
      <action android:name="android.intent.action.MAIN"/>
      <category android:name="android.intent.category.LAUNCHER"/>
  </intent-filter>
  ```
- Read its `android:name` — that is the main entry Activity (fully qualified
  `<package>.<Name>Activity`). There is exactly one such filter per launcher.
- Note: a hardener may use a *proxy* Application + a secondary (packed) dex. The
  manifest `android:name` on `<application>` names the real `Application` class;
  if that class only does `attachBaseContext` unpacking, the *functional* entry
  lives in the decrypted secondary dex (see `encrypted-secondary-dex.md`).

## Background-running capability — Q "是否有后台运行权限"

Look for evidence that the app runs or persists in the background:

- **Foreground service**: `<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>`.
- **Boot auto-start**: a `<receiver>` with
  `<action android:name="android.intent.action.BOOT_COMPLETED"/>` (and often
  `CONNECTIVITY_CHANGE`). This restarts the app after reboot.
- **Keep-alive service**: a `<service>` named like `KeepAliveService` /
  `PushService` with `android:exported="true"` and `android:enabled="true"`.
- **Wake lock**: `<uses-permission android:name="android.permission.WAKE_LOCK"/>`.
- **Push SDKs**: Xiaomi/Meizu/Huawei/Oppo push services + their `RECEIVE`
  receivers — these keep a persistent channel.

Answer "有" when any of boot-receiver / foreground-service / keep-alive service
is present; "无" otherwise. Report the specific manifest lines as evidence.

## Permissions triage

- `INTERNET`, `ACCESS_NETWORK_STATE` ⇒ network comms (correlate with `pcap`.
- `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`, `WAKE_LOCK` ⇒ persistence.
- `READ/WRITE_EXTERNAL_STORAGE`, `CAMERA`, `RECORD_AUDIO`, `READ_PHONE_STATE`,
  `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES` ⇒ capability surface — note
  them but don't over-claim behavior from a permission alone.
