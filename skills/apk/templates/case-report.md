# Case report — APK static analysis

Consolidated output for one sample. Keep findings ordered by the original
question numbering, but do **not** embed answer values here if this report will
be shared as a skill — keep answers in private case notes and present only the
method/structure.

```
# APK analysis report — <sample name / sha256>

## 1. Evidence
- Source: <evidence path / how obtained>
- SHA-256: <apk hash>
- Tools: jadx <ver>, unzip, strings, tshark <ver>

## 2. Manifest findings
- Package: <package>
- Launcher activity: <activity>  [VERIFIED]
- Background-running: 有/无  [VERIFIED/SUPPORTED]  evidence: <lines>

## 3. Native libraries
- loadLibrary: <base> -> lib<base>.so  [VERIFIED]
- JNI surface: <Java_... symbols>
- Key literal (if any): <key> @ offset  [VERIFIED/UNRESOLVED]
- Algorithm: <ALGORITHM>  [SUPPORTED]  evidence: <symbols>

## 4. Encrypted payload / asset
- Payload files: <*.ccb / assets/...>
- decrypt() call site: <file:line>
- Decrypted file name: <name>  [VERIFIED/UNRESOLVED]
- Decryption key: <key>  [VERIFIED/UNRESOLVED]
- Config file for recovered key: <name>  [VERIFIED/UNRESOLVED]

## 5. Escalation (if any)
- <Ghidra/IDA on .so decrypt, or isolated sandbox trace of unpacking>

## 6. Verification summary
| claim | level | evidence |
|-------|-------|----------|
| ...   | ...   | ...      |
```
