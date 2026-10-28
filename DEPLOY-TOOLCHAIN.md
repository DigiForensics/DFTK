# External tools, optional libraries and OCR models

DFTK has three distinct dependency groups: Python extras, external executables
and local OCR weights. Installing/registering one does not install the others.
Use a trusted tool distribution and keep its writable installation outside source
evidence. The full list of discovered tools is returned by `dftk doctor`.

## Python integrations

Install only the extras the task needs; see [README](README.md#optional-integrations).
`mcp`, `media`, `ocr`, `windows`, `image`, `ese`, `email`, `ssh` and `yara` select
different dependencies. `all` includes large OCR and native-binding dependencies;
it is not a universally portable one-step toolchain installation.

For offline installation, prepare the wheel and all required dependency wheels on
an authorised connected machine, transfer the trusted wheelhouse, then install:

```bash
python -m pip install --no-index --find-links /opt/wheelhouse "dftk[mcp,media]"
```

Zero mandatory core dependencies does not make an online `pip install` work when
PyPI is unreachable. Use a local wheel/check-out or an explicit package mirror.

## Register an extracted executable bundle

`dftk prepare` records a trusted toolkit root and can generate launch shims. It
does not download tools, acquire licences or add adapters for arbitrary commands.

```bash
dftk prepare /opt/forensic-tools
dftk prepare --show
dftk doctor
```

In PowerShell use `dftk prepare 'E:\TOOLKIT'`; POSIX shells require their own
quoting/path conventions. Configuration defaults to `~/.dftk/toolchain.json`
(`DFTK_TOOLCHAIN_CONFIG` can override it), and shims to `~/.dftk/bin`.
Management commands write configuration/launchers; they are not READ_ONLY evidence
capabilities. Do not point preparation at acquired evidence.

| Option | Effect |
|---|---|
| `--no-shims` | Record the toolkit root without generating launchers |
| `--bin-dir DIR` | Choose the generated shim directory |
| `--rewrite-from OLD_ROOT` | Explicitly rewrite stale roots in trusted `.bat`/`.cmd`/`.ps1` launchers, retaining backups |
| `--show` | Inspect current configuration |

The resolver checks PATH, per-category `DFTK_*_TOOL_DIRS`, configured toolkit
locations and managed shims. Search is bounded; tools buried deeper may need a
category directory or explicit PATH entry. The generated `set_path.sh` / `.bat`
helpers affect a terminal session only; preparation does not rewrite system PATH.
Java/other runtime requirements still belong to the external tool's installation.

When a registered capability declares a missing executable dependency it returns
UNSUPPORTED with the requirement. Discovery alone does not mean DFTK implements
that executable's functionality. For example, six `memory.*` operations adapt
fixed Volatility plugins; discovering IDA does not create an arbitrary IDA command
interface. OpenSSL decryption uses the resolver, including `DFTK_CRYPTO_TOOL_DIRS`.

## Media-specific setup

Image operations need Pillow (`media` extra). OCR adds EasyOCR, PyTorch and related
packages; choose a PyTorch build compatible with the host's CUDA or Apple MPS
environment. Provision trusted detection/recognition weights before examination
and set `DFTK_OCR_MODEL_DIR` to that existing directory. The default is
`~/.EasyOCR/model`. DFTK disables EasyOCR model downloads during examination.

GPU-only MPS execution rejects `PYTORCH_ENABLE_MPS_FALLBACK=1`; do not silently
enable CPU fallback. CPU OCR is selected only after affirmative user consent.
`doctor` reports the model directory and configuration but does not initialise
GPU models or prove that the selected weights/languages will run.

Video metadata and frame sampling invoke `ffprobe` / `ffmpeg` through PATH,
separately from the general toolkit resolver. Install both in the environment
visible to the MCP process. Supported signatures/decoders remain bounded;
extension discovery is not a decoding guarantee.
[Media setup and limits](docs/media-perception.md)
