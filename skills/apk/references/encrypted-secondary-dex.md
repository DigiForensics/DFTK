# Encrypted secondary dex (packing / .ccb)

Many hardened APKs do **not** ship their real logic in `classes.dex`. Instead a
small *proxy* `Application` (often the `android:name` on `<application>`) at
startup unpacks and decrypts additional dex files, then loads them by
reflection.

## Detection signals

In the decompiled `Application` (e.g. `attachBaseContext` / `onCreate`):

- Unzip the APK into a private dir:
  `unZipApk(apkFile, appDir)`.
- Loop over files ending in a custom extension (`.ccb`, `.jiagu`, `.payload`,
  …) and call a **native** `decrypt(byte[], String)` on each:
  ```java
  if (file.getName().endsWith(".ccb") ...) {
      byte[] bytes = getBytes(file);
      decrypt(bytes, file.getAbsolutePath());   // native, in-place
  }
  ```
- Reflection-based classloader injection:
  ```java
  Field pathList = reflexField(getClassLoader(), "pathList");
  Object[] addElements = makePathElements.invoke(pathList, dexFiles, ...);
  // arraycopy into dexElements
  ```
  This is the classic "load secondary dex without `MultiDex`" pattern.

## Characterizing the payload

```
python - <<'PY'
import zipfile
with zipfile.ZipFile("sample.apk") as z:
    for n in z.namelist():
        if n.endswith(".ccb"):
            d = z.read(n)
            print(n, len(d), d[:16].hex())   # random-looking => encrypted
PY
```
If the first bytes are **not** `dex\n035` / `dex\n037` / `PK\x03\x04`, the
payload is encrypted. The native `decrypt` turns it into a runnable dex.

## What this means for the questions

Any behavior (decrypting an `assets/<file>` payload, the key that decrypts it,
the config file where a recovered secret is persisted) that the *functional* app
performs usually lives in this **decrypted secondary dex**, NOT in the proxy
`classes.dex` you first decompiled.

## Escalation

Static-only you can **confirm the packing exists** and **name the payload files
& the native `decrypt`**, but you cannot read the plaintext inside without:

- reversing the `.so`'s `decrypt` JNI function (key + mode + IV) in Ghidra/IDA,
  then replicating it in Python (pycryptodome) to decrypt the `.ccb`; or
- capturing the unpacked dex from an isolated, snapshot-revertible emulator (the
  app writes the decrypted `.ccb`/dex to its private dir at runtime).

Mark any value that only exists inside the payload as **UNRESOLVED** and state
this path. Do not guess the key from the proxy dex.
