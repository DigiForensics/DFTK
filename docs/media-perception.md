# Media perception for an Agent

DFTK provides evidence access, bounded execution and source-linked memory. The
host Agent chooses what to examine, connects observations and assesses claims.
No fixed investigation sequence is required.

## Discovery and consent

`evidence.intake` and `evidence.browse` discover images/videos without sending
pixels to a model. Intake keeps extension hints beyond its signature-inspection
budget, identifies OpenSSL `Salted__` headers, and retains unread content in the
Case inventory. `media.inspect` reads image dimensions/EXIF or FFprobe metadata;
this is not visual content examination. Unsupported formats remain visible gaps.

Before visual disclosure the host must know its current model supports images
and obtain the user's consent for the file or defined scope. Existing in-scope
consent can be reused. Developing DFTK or permission for metadata/local OCR does
not itself authorise sending media to a model.

```text
dftk_view_media(path="photos/screen.png", case_id="...",
                user_authorized=true, model_supports_images=true)
```

Both flags default false. With either false, no pixels are decoded or returned.
Tell the user which media was found and why visual review has not happened.
DFTK cannot authenticate chat approval or infer model modalities: these flags
are host attestations, not a separate user-authentication mechanism.

The MCP reply contains native image content plus source hashes/locators. Pixels
are transport-only; Case files, summaries, exports and paging do not replay them.
Subsequent visual requests also need valid scoped consent. Install optional image
support with `pip install "dftk[media]"`.

For an overview, supply `paths=["photos/a.png","photos/b.png"]` instead of
`path`. The contact sheet accepts up to 16 still images and maps each numbered
thumbnail to its source path, SHA-256 and sheet coordinates. Consent must cover
every input. A corrupt image gets its own failure entry while other images remain
available. Thumbnails are an overview, not detailed review.

For small text/details, request a single image with
`crop_box=[left,top,right,bottom]`. Coordinates refer to EXIF-oriented source
pixels before resizing; `media.inspect` returns `exif_oriented_size`. Out-of-range
crops fail rather than silently selecting a different region. The reply records
the source dimensions and exact crop. Cropping does not apply to video.

## Video scope

The stdio adapter presents video through timestamped frames to image-capable
models, without uploading the full video or audio:

```text
dftk_view_media(path="camera.mp4", case_id="...", user_authorized=true,
                model_supports_images=true, start_seconds=10,
                interval_seconds=5, frame_count=4)
```

Install FFmpeg/FFprobe separately. Calls return at most eight scaled frames and
4 MiB of JPEG payload. The reply lists requested sample positions and dimensions;
these are not frame-accurate acquisition-time claims. Unsampled motion, other
frames and audio remain unexamined. Image previews are EXIF-oriented, resized
first-frame images; small text may require a source-coordinate crop.
Finding a format does not guarantee the installed decoder supports it.

## Local OCR: GPU first, CPU only by consent

Install `pip install "dftk[ocr]"` with a PyTorch build for the host's CUDA/Apple
MPS environment. Provision trusted EasyOCR weights separately and set
`DFTK_OCR_MODEL_DIR` to their existing directory (default `~/.EasyOCR/model`).
Examination calls never download weights or upload evidence. See the
[EasyOCR API](https://jaided.ai/easyocr/documentation/) for language/model setup.

```text
dftk_run(name="media.ocr", case_id="...",
         params={"path":"photos/screen.png", "languages":["ch_sim","en"]})
```

The runtime selects CUDA then MPS. No GPU returns `cpu_consent_required` without
opening the image or starting CPU inference. GPU initialisation/inference errors
are explicit; there is no CPU retry. Tell the user CPU OCR may be very slow and
ask whether to proceed. Only an affirmative answer authorises a new call with
`allow_cpu=true`, explicitly selecting CPU even after GPU failure. Vision consent
does not authorise CPU fallback.

OCR is local and independent of the host model's image support. Results carry
text, processed boxes, source-coordinate boxes, confidence, original/processed
dimensions, hashes and video sample positions. Still-image `crop_box` uses the
same coordinates as preview. Video boxes refer to the decoded, scaled frame;
they are not original sensor coordinates. Errors/empty text do not establish
absence. Recognition accuracy and speed depend on hardware, models and evidence.

`media.ocr_batch` processes up to 32 still images with one model initialisation.
Each file has its own status, hash and source-linked rows; a corrupt image does
not discard earlier results. GPU inference failure stops remaining inputs without
CPU fallback. `time_budget_seconds` (default 90) includes initialisation and is
checked between images. It is a cooperative budget, not a hard inference deadline;
the server's process timeout still applies. Completed calls return
`remaining_paths`, so resume those inputs instead of rerunning completed images.
Batch OCR does not decode video or accept a per-file crop; use `media.ocr` for
timestamped video frames or a selected image region.

## Evidence memory and composable actions

Page the merged inventory with `dftk_case(action="artifacts", case_id="...",
offset=0, limit=100)`. Metadata, previews and OCR are recorded separately. Use
`note_artifact` with a reason and disposition `reviewed`, `deferred`,
`user_declined`, `model_unsupported` or `not_relevant`. Declined/deferred items
remain coverage gaps. These notes are analyst assertions, not proof of review.

Archive inventory exposes encrypted members and paging. Extraction accepts one
supplied ZIP password, preserves accessible members when others need passwords,
and never guesses. Some AES ZIP methods and RAR/7z decoding remain unsupported
by these operations. Continue other evidence when a branch is blocked.

`crypto.openssl_decrypt` makes one supplied-password OpenSSL `enc` attempt. It
requires explicit `cipher`, `kdf`, `expected_kind`, and a `key_evidence` citation;
a `Salted__` header alone does not establish these parameters. Supported outputs
are ZIP, SQLite, GZIP and raw TAR, with AES CBC/CTR and PBKDF2/legacy derivation.
This STATEFUL capability needs a server policy allowing derived workspace output.
The password travels through stdin, not argv, and is redacted from Case run and
attempt parameters. Keep secrets out of the citation/report text.
`key_evidence` is a host-supplied reference; the runtime does not verify that the
referenced source actually contains the candidate or establishes the parameters.

Only structurally validated plaintext becomes a registered derived input. ZIP
checks its central directory, not member contents/CRC; SQLite uses `quick_check`
without sidecars; GZIP verifies its stream/CRC within a 64 MiB expansion bound;
TAR checks bounded member headers. These checks do not authenticate the encryption
parameters or acquisition origin. Failed candidates, timeouts and invalid inner
formats publish no output. There is no internal candidate generation or retry;
the host should stop equivalent failures until new evidence changes the hypothesis.

In a Case, extracted archive/filesystem/HTTP outputs have concrete paths and
digests. Later evidence-input tools can read these exact workspace files after
digest validation. Arbitrary workspace files and altered outputs remain blocked.
Use the same Case ID throughout the extraction-to-analysis chain.

Large Recipe facts have unique keys for repeated tools. `dftk_read_case_run`
accepts JSON Pointers such as `/browser.chromium_history/visits`; `~1` escapes a
slash and `~0` a tilde. `fact_pointers` lists top-level addresses. Paging metadata
does not duplicate child Observations/provenance. To read provenance, select
`section="meta", fact_path="/provenance/artifacts"`; select
`section="derived_artifacts"` to page derived outputs. The CLI provides
`case artifacts` and `case note-artifact` with the same inventory semantics.
Worker attempts are recorded before work,
so timeouts remain visible even without a completed Observation.
