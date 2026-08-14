# Native libraries: loadLibrary name & JNI surface

When `System.loadLibrary("base")` appears, the real library file is
`lib/lib<abi>/libbase.so` inside the APK (one per ABI: `arm64-v8a`,
`armeabi-v7a`, `x86_64`, …). The `loadLibrary("base")` name maps to
`libbase.so`.

## Finding the loaded library — Q "加载的 so 库名称"

```
grep -rn 'System.loadLibrary(' sources
```
The argument string is the base name; report `lib<arg>.so`.

## Extracting the .so

APK is a ZIP. Pull only the native libs:
```python
import zipfile, os
with zipfile.ZipFile("sample.apk") as z:
    for n in z.namelist():
        if n.startswith("lib/") and n.endswith(".so"):
            p = os.path.join("out", *n.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(z.read(n))
```
Prefer the `arm64-v8a` build (largest, most representative) for analysis.

## JNI surface = the native API the app calls

Native methods declared in the Java side:
```java
public static native String getA();
public static native void decrypt(byte[] data, String outPath);
```
Each maps to a symbol `Java_<pkg>_<Class>_<method>` in the `.so`. List them:
```
strings libxxx.so | grep Java_
```
This tells you **what** the native side returns (a key? a decrypted buffer?)
without disassembling — e.g. `getA`..`getE` likely return key fragments;
`decrypt` performs the in-place decryption of a payload file.

## When the .so matters

- Recovering a hardcoded key string that the app reads from the library.
- Confirming the crypto algorithm family (see `string-and-key-recovery.md`).
- Understanding the unpacking entry used by a packed secondary dex.

For actual algorithm/key recovery that is not a plaintext literal, escalate to
`reverse-exe` (disassemble the `.so` with Ghidra/IDA); this skill stops at the
static string/constant level.
