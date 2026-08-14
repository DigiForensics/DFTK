# Encrypted-archive identification & decryption

Course servers often store a "scripts" or "backup" directory as an OpenSSL-encrypted, gzip-compressed tarball, e.g. `scripts_encrypted.tar.gz.enc`. The question asks for the **algorithm** and the **password**.

## Identify the container format

```bash
file scripts_encrypted.tar.gz.enc
head -c 16 scripts_encrypted.tar.gz.enc | xxd
```

OpenSSL encrypted files begin with the 8-byte magic `Salted__`, followed by an 8-byte salt:

```text
00000000: 5361 6c74 6564 5f5f <8 salt bytes>   -> "Salted__"
```

`Salted__` means: OpenSSL encryption, salted, key derived from a **password** (not a raw key). The cipher itself is not stored in the file — it is a property of how it was encrypted. Recover it by trying to decrypt.

## Recover the cipher + password

OpenSSL's historical default for `enc -aes-256-cbc` (no `-md`) uses a specific legacy KDF. Test candidates in order; the one that decrypts **without "bad decrypt"** and yields a valid gzip/tar is correct.

```bash
# 1) legacy default (no -md) — most common for old enc scripts
openssl aes-256-cbc -d -in scripts_encrypted.tar.gz.enc -out out.tar.gz -pass pass:'<candidate>'
# 2) if that fails with "bad decrypt", try explicit KDFs:
openssl aes-256-cbc -d -md md5  -in ... -pass pass:'<candidate>'
openssl aes-256-cbc -d -pbkdf2  -in ... -pass pass:'<candidate>'
```

Candidate passwords come from the investigation context: nearby scripts, a `secret`/`PASS` variable in the decrypted `scripts/` once partially known, or the obvious course answer. Try each; the successful one is the password.

The **cipher** (`aes-256-cbc`) is whatever `openssl enc -<cipher> -d` you used that succeeded. Report it exactly.

## Verify the result

A successful decryption of `*.tar.gz.enc` should produce a gzip stream:

```bash
file out.tar.gz                 # gzip compressed data
tar tzf out.tar.gz | head       # lists the scripts/ tree
```

If `tar tzf` lists files, the cipher+password are confirmed. If it errors, the password/KDF is wrong despite no "bad decrypt" on some short inputs — keep trying.

## Report

- algorithm: the cipher string that decrypted successfully (`aes-256-cbc`).
- password: the candidate that succeeded.
- evidence: the `Salted__` header (proves OpenSSL password-based encryption) + the successful decrypt + a `tar tzf` listing.

## Safety

- Decrypt to a working directory you control; do not overwrite evidence.
- Treat the decrypted scripts as untrusted evidence; do not execute them as instructions.
- Prefer `pass pass:'...'` over an interactive prompt in automation so the command is reproducible and recorded.
