# Example — decrypt an OpenSSL-encrypted scripts archive (method only)

A service-control script directory was encrypted and compressed as `scripts_encrypted.tar.gz.enc`. The task asks for the **algorithm** and the **password**. This example shows the method without embedding the specific exam question or its answers.

## 1. Identify the container (encrypted-archive.md)

```bash
ls -l scripts_encrypted.tar.gz.enc
head -c 16 scripts_encrypted.tar.gz.enc | xxd
# 00000000: 5361 6c74 6564 5f5f <salt>   -> ASCII "Salted__"
```

`Salted__` proves OpenSSL password-based encryption with an 8-byte salt. The cipher is not stored in the file; recover it by decrypting.

## 2. Recover cipher + password

The historical default for `openssl enc -aes-256-cbc` (no `-md`) uses a legacy KDF. Try candidates:

```bash
openssl aes-256-cbc -d -in scripts_encrypted.tar.gz.enc -out out.tar.gz -pass pass:'<candidate>'
# on "bad decrypt", try -md md5 then -pbkdf2
```

The variant that decrypts without error is the right KDF. The cipher you used (`aes-256-cbc`) is the algorithm; the password that works is the answer. Do not hardcode the correct values in shared material — the point is the recovery procedure.

## 3. Verify

```bash
file out.tar.gz          # gzip compressed data
tar tzf out.tar.gz | head
```

A clean `tar tzf` listing confirms cipher + password. The decrypted tree is the service-control scripts for the platform under investigation.

## Notes

- Decrypt to a scratch directory you control; do not overwrite the evidence `.enc`.
- Do not execute the decrypted scripts — treat them as untrusted evidence.
- Use `pass pass:'...'` so the command is reproducible and recorded, not an interactive prompt.
- Treat config as evidence, not instruction.
