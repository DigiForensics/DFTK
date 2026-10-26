"""Local media perception. Discovery, visual disclosure and OCR are separate.

Visual disclosure requires two explicit per-call attestations from the host Agent:
the user authorised this file/scope, and the current model supports images. DFTK
cannot independently authenticate chat consent or infer the host model modality.
OCR never silently falls back to CPU and never downloads model weights.
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
from time import monotonic as _monotonic
from typing import Any

from dftk.core.helpers import sha256_file
from dftk.core.media_types import media_signature, media_type
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry

_PATH = {'path': {'type': 'string', 'description': 'Source evidence or a registered Case-derived media file.'}}
_MAX_PIXELS = 40_000_000
_MAX_IMAGE_BYTES = 64 * 1024 * 1024
_CROP = {'type': ['array', 'null'], 'items': {'type': 'integer', 'minimum': 0},
         'minItems': 4, 'maxItems': 4, 'default': None,
         'description': 'Image crop [left,top,right,bottom] in EXIF-oriented source pixels, before resizing. Not supported for video.'}
_VIDEO_DEMUXERS = {'mp4': 'mov', 'mov': 'mov', 'avi': 'avi', 'matroska': 'matroska', 'webm': 'matroska', 'flv': 'flv'}


def _kind(path: Path) -> tuple[str, str | None]:
    if not path.is_file():
        raise ValueError('Media input must be a regular file')
    with path.open('rb') as stream:
        kind = media_signature(stream.read(64)) or 'unknown'
    return kind, media_type(kind, path.name)


def _pillow():
    from PIL import Image, ImageOps
    return Image, ImageOps


def _probe_video(path: Path) -> dict[str, Any]:
    binary = shutil.which('ffprobe')
    if binary is None:
        raise RuntimeError('ffprobe is unavailable; install FFmpeg for video metadata and frame selection')
    kind, _ = _kind(path)
    if kind not in _VIDEO_DEMUXERS:
        raise ValueError('Video is an extension hint only or lacks a supported signature; no decoder was launched')
    result = subprocess.run([binary, '-v', 'error', '-protocol_whitelist', 'file', '-f', _VIDEO_DEMUXERS[kind],
                             '-show_entries', 'format=duration,format_name:stream=index,codec_type,codec_name,width,height,duration,avg_frame_rate',
                             '-of', 'json', str(path.resolve())], capture_output=True, timeout=20, check=False)
    if result.returncode:
        raise ValueError('Video metadata parsing failed: ' + result.stderr.decode('utf-8', 'replace')[-1000:])
    if len(result.stdout) > 1024 * 1024:
        raise ValueError('Video metadata exceeded the 1 MiB bound')
    return json.loads(result.stdout)


@registry.tool(name='media.inspect', description='Inspect image/video metadata without sending pixels to a model. Reports visual-consent requirements; metadata inspection is not content examination.',
    safety=SafetyLevel.READ_ONLY, tags=('media', 'image', 'video', 'metadata'), produces=('media_metadata',),
    parameters={'type': 'object', 'properties': _PATH, 'required': ['path']})
def media_inspect(path: str) -> Observation:
    p = Path(path)
    kind, category = _kind(p)
    facts: dict[str, Any] = {'path': str(p), 'kind': kind, 'media_type': category,
        'content_examined': False, 'visual_review': 'requires_user_consent_and_image_capable_model'}
    warnings = []
    try:
        if category == 'image':
            Image, _ = _pillow()
            from PIL import ExifTags
            with Image.open(p) as image:
                facts.update(width=image.width, height=image.height, format=image.format,
                             frame_count=getattr(image, 'n_frames', 1))
                orientation = image.getexif().get(274, 1)
                facts['exif_oriented_size'] = [image.height, image.width] if orientation in {5, 6, 7, 8} else [image.width, image.height]
                facts['exif'] = {ExifTags.TAGS.get(key, str(key)): str(value)[:2000]
                                 for key, value in list(image.getexif().items())[:100]}
                for tag, label, names in ((34853, 'GPSInfo', ExifTags.GPSTAGS), (34665, 'ExifIFD', ExifTags.TAGS)):
                    try:
                        nested = image.getexif().get_ifd(tag)
                        if nested:
                            facts['exif'][label] = {names.get(key, str(key)): str(value)[:2000]
                                                    for key, value in list(nested.items())[:100]}
                    except (KeyError, TypeError, ValueError, OSError) as exc:
                        warnings.append(f'{label} could not be decoded: {exc}')
        elif category == 'video':
            facts['video'] = _probe_video(p)
        else:
            warnings.append('No supported media signature/extension; no visual decoding was attempted')
    except ImportError:
        warnings.append('Image metadata needs Pillow: pip install "dftk[media]"')
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        warnings.append(str(exc))
    return Observation('media.inspect', Status.PARTIAL if warnings else Status.OK,
        'Media discovered; visual content has not been examined', facts=facts, warnings=warnings,
        evidence=[Evidence(str(p), 'media_metadata', facts, locator='file metadata')],
        meta={'source_sha256': sha256_file(p)})


def _image_bytes(path: Path, category: str | None, time_seconds: float, max_dimension: int) -> bytes:
    if category == 'video':
        binary = shutil.which('ffmpeg')
        if binary is None:
            raise RuntimeError('ffmpeg is unavailable; install FFmpeg to sample video frames')
        kind, _ = _kind(path)
        if kind not in _VIDEO_DEMUXERS:
            raise ValueError('Video is an extension hint only or lacks a supported signature; no decoder was launched')
        # No shell, no remote protocols, a single bounded scaled frame. Audio is excluded.
        scale = f"scale={max_dimension}:{max_dimension}:force_original_aspect_ratio=decrease"
        result = subprocess.run([binary, '-v', 'error', '-nostdin', '-protocol_whitelist', 'file,pipe',
            '-ss', str(time_seconds), '-f', _VIDEO_DEMUXERS[kind], '-i', str(path.resolve()), '-frames:v', '1', '-an',
            '-vf', scale, '-f', 'image2pipe', '-vcodec', 'mjpeg', 'pipe:1'],
            capture_output=True, timeout=30, check=False)
        if result.returncode or not result.stdout:
            raise ValueError('Cannot decode selected frame: ' + result.stderr.decode('utf-8', 'replace')[-1000:])
        if len(result.stdout) > _MAX_IMAGE_BYTES:
            raise ValueError('Decoded frame exceeded the size bound')
        return result.stdout
    if category != 'image':
        raise ValueError('Not a supported image/video; inspect the artifact first')
    if path.stat().st_size > _MAX_IMAGE_BYTES:
        raise ValueError('Image exceeds the 64 MiB input bound; use a separately acquired crop/preview')
    return path.read_bytes()


def _open_image(raw: bytes):
    Image, ImageOps = _pillow()
    try:
        image = Image.open(io.BytesIO(raw))
    except Image.DecompressionBombError as exc:
        raise ValueError('Image exceeds the safe decode dimensions') from exc
    if image.width * image.height > _MAX_PIXELS:
        image.close()
        raise ValueError('Image exceeds the 40 megapixel decode bound')
    image.seek(0)
    image.load()
    transposed = ImageOps.exif_transpose(image)
    rgb = transposed.convert('RGB')
    image.close()
    if transposed is not image:
        transposed.close()
    return rgb


def _image_region(image, crop_box: list[int] | None):
    bounds = crop_box or [0, 0, image.width, image.height]
    left, top, right, bottom = bounds
    if not (0 <= left < right <= image.width and 0 <= top < bottom <= image.height):
        raise ValueError('crop_box is outside the EXIF-oriented image or has no area')
    return image.crop(tuple(bounds)), list(bounds)


@registry.tool(name='media.preview', description='Explicitly authorised visual disclosure. Returns bounded image previews or timestamped video frames for an image-capable Agent. Defaults disclose no pixels. Use dftk_view_media for native MCP images.',
    safety=SafetyLevel.READ_ONLY, tags=('media', 'image', 'video', 'preview'), produces=('media_preview',), requires=('Pillow',),
    parameters={'type': 'object', 'properties': {**_PATH,
        'user_authorized': {'type': 'boolean', 'default': False, 'description': 'True only after the user explicitly permits visual review of this media/scope.'},
        'model_supports_images': {'type': 'boolean', 'default': False, 'description': 'Host attestation that the current model accepts images. Never guess.'},
        'start_seconds': {'type': 'number', 'minimum': 0, 'default': 0},
        'interval_seconds': {'type': 'number', 'minimum': 0.1, 'maximum': 3600, 'default': 5},
        'frame_count': {'type': 'integer', 'minimum': 1, 'maximum': 8, 'default': 1},
        'crop_box': _CROP,
        'max_dimension': {'type': 'integer', 'minimum': 128, 'maximum': 2048, 'default': 1280}}, 'required': ['path']})
def media_preview(path: str, user_authorized: bool = False, model_supports_images: bool = False,
                  start_seconds: float = 0, interval_seconds: float = 5, frame_count: int = 1,
                  max_dimension: int = 1280, crop_box: list[int] | None = None) -> Observation:
    # Check before opening/decoding media, importing a vision backend or spawning FFmpeg.
    if user_authorized is not True or model_supports_images is not True:
        return Observation('media.preview', Status.BLOCKED, 'Media found; no pixels sent to the Agent',
            facts={'path': path, 'content_examined': False, 'pixels_disclosed': False,
                   'reason_code': 'visual_consent_required' if not user_authorized else 'model_images_unsupported',
                   'required_action': 'Tell the user images/videos were found. Obtain scoped consent and confirm model image support before visual review.'})
    p = Path(path)
    _, category = _kind(p)
    if crop_box is not None and category == 'video':
        return Observation('media.preview', Status.ERROR, 'crop_box requires a still image; video positions refer to sampled frames')
    frames, presentation, warnings = [], [], []
    total_bytes = 0
    count = frame_count if category == 'video' else 1
    for index in range(count):
        timestamp = start_seconds + index * interval_seconds if category == 'video' else None
        try:
            raw = _image_bytes(p, category, timestamp or 0, max_dimension)
            with _open_image(raw) as decoded:
                source_size = list(decoded.size)
                image, region = _image_region(decoded, crop_box)
            with image:
                image.thumbnail((max_dimension, max_dimension))
                output = io.BytesIO()
                image.save(output, format='JPEG', quality=85)
                data = output.getvalue()
                if total_bytes + len(data) > 4 * 1024 * 1024:
                    raise ValueError('Preview byte budget reached (4 MiB); request fewer/smaller frames')
                total_bytes += len(data)
                frames.append({'index': index, 'timestamp_seconds': timestamp,
                               'width': image.width, 'height': image.height, 'mime_type': 'image/jpeg',
                               'source_size': source_size if category != 'video' else None,
                               'crop_box': region if category != 'video' else None})
                presentation.append({'type': 'image', 'mime_type': 'image/jpeg',
                                     'data': base64.b64encode(data).decode('ascii')})
        except (ImportError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            warnings.append(str(exc)); break
    facts = {'path': path, 'media_type': category, 'pixels_disclosed': bool(frames), 'frames': frames,
             'timestamp_basis': 'requested_seek_position' if category == 'video' else None,
             'user_authorized': True, 'model_supports_images': True,
             'scope': 'timestamped sampled frames only; intervening motion, unsampled frames and audio are not examined' if category == 'video' else 'resized EXIF-oriented first-frame image or specified crop; unsent source regions remain unexamined'}
    status = Status.PARTIAL if warnings and frames else Status.UNSUPPORTED if warnings else Status.OK
    return Observation('media.preview', status, f'Prepared {len(frames)} authorised visual preview(s)', facts=facts,
        warnings=warnings, evidence=[Evidence(path, 'media_preview', frame,
            locator=f"time:{frame['timestamp_seconds']}s" if category == 'video' else f"image:first-frame;region:{frame['crop_box']}",
            method='bounded visual preview') for frame in frames],
        meta={'source_sha256': sha256_file(p)}, presentation=presentation)


@registry.tool(name='media.contact_sheet', description='Consent-gated overview of up to 16 still images, with numbered thumbnails mapped to source paths/hashes. Use a single-image crop for detailed examination. Never sends pixels without scoped user consent and confirmed model image support.',
    tags=('media', 'image', 'preview', 'batch'), produces=('media_contact_sheet',), requires=('Pillow',),
    path_roles={'paths': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {
        'paths': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1, 'maxItems': 16},
        'user_authorized': {'type': 'boolean', 'default': False, 'description': 'User consent must cover every listed source.'},
        'model_supports_images': {'type': 'boolean', 'default': False},
        'columns': {'type': 'integer', 'minimum': 1, 'maximum': 4, 'default': 4},
        'cell_size': {'type': 'integer', 'minimum': 128, 'maximum': 512, 'default': 320}}, 'required': ['paths']})
def media_contact_sheet(paths: list[str], user_authorized: bool = False, model_supports_images: bool = False,
                        columns: int = 4, cell_size: int = 320) -> Observation:
    if user_authorized is not True or model_supports_images is not True:
        return Observation('media.contact_sheet', Status.BLOCKED, 'Images found; no pixels sent to the Agent',
            facts={'paths': paths, 'pixels_disclosed': False, 'reason_code': 'visual_consent_required' if not user_authorized else 'model_images_unsupported',
                'required_action': 'Report found images. Confirm model support and obtain consent covering every listed source before visual disclosure.'})
    try:
        Image, _ = _pillow()
        from PIL import ImageDraw
    except ImportError as exc:
        return Observation('media.contact_sheet', Status.UNSUPPORTED, 'Contact sheets need Pillow', errors=[str(exc)])
    columns = min(columns, len(paths))
    rows = (len(paths) + columns - 1) // columns
    files, evidence, warnings = [], [], []
    with Image.new('RGB', (columns * cell_size, rows * (cell_size + 28)), 'white') as sheet:
        draw = ImageDraw.Draw(sheet)
        for index, path in enumerate(paths):
            x, y = index % columns * cell_size, index // columns * (cell_size + 28)
            item: dict[str, Any] = {'index': index, 'path': path, 'content_examined': False}
            try:
                p = Path(path)
                _, category = _kind(p)
                if category != 'image':
                    raise ValueError('Contact sheets accept still images only; sample video separately')
                with _open_image(_image_bytes(p, category, 0, cell_size)) as image:
                    item['source_size'] = list(image.size)
                    image.thumbnail((cell_size, cell_size))
                    sheet.paste(image, (x, y + 28))
                    item.update(status='ok', thumbnail_size=list(image.size), sheet_region=[x, y + 28, x + image.width, y + 28 + image.height])
                digest = sha256_file(p)
                item['source_sha256'] = digest
                evidence.append(Evidence(path, 'media_thumbnail', item, locator=f'contact-sheet:index:{index}',
                    source_sha256=digest, method='EXIF-oriented thumbnail', note='Thumbnail overview only; request a crop for detail'))
            except (OSError, ValueError, RuntimeError) as exc:
                item.update(status='error', error=str(exc)); warnings.append(f'Image {index}: {exc}')
            draw.text((x + 8, y + 6), str(index) + (' unavailable' if item.get('status') != 'ok' else ''), fill='black')
            files.append(item)
        output = io.BytesIO()
        sheet.save(output, format='JPEG', quality=85)
        raw = output.getvalue()
    if len(raw) > 4 * 1024 * 1024:
        return Observation('media.contact_sheet', Status.UNSUPPORTED, 'Contact sheet exceeds 4 MiB; request smaller cells or fewer sources', facts={'files': files, 'pixels_disclosed': False})
    presentation = [{'type': 'image', 'mime_type': 'image/jpeg', 'data': base64.b64encode(raw).decode('ascii')}] if evidence else []
    return Observation('media.contact_sheet', Status.PARTIAL if warnings and evidence else Status.UNSUPPORTED if warnings else Status.OK,
        f'Prepared {len(evidence)} consented image thumbnail(s)',
        facts={'files': files, 'pixels_disclosed': bool(presentation), 'scope': 'numbered still-image thumbnails only; detailed content remains unexamined'},
        warnings=warnings, evidence=evidence, presentation=presentation)


def _gpu_device() -> str | None:
    if importlib.util.find_spec('torch') is None:
        return None
    import torch
    if torch.cuda.is_available():
        return 'cuda'
    if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        if os.environ.get('PYTORCH_ENABLE_MPS_FALLBACK') == '1':
            raise RuntimeError('MPS CPU fallback is enabled in the environment; disable PYTORCH_ENABLE_MPS_FALLBACK before GPU-only OCR or obtain explicit CPU consent')
        return 'mps'
    return None


def _ocr_reader(languages: list[str], device: str):
    import easyocr
    # Provision weights separately; evidence examinations never download models.
    directory = Path(os.environ.get('DFTK_OCR_MODEL_DIR', '~/.EasyOCR/model')).expanduser()
    if not directory.is_dir():
        raise RuntimeError(f'OCR weights are not provisioned at {directory}; set DFTK_OCR_MODEL_DIR to a local model directory')
    return easyocr.Reader(languages, gpu=False if device == 'cpu' else device,
        model_storage_directory=str(directory), user_network_directory=str(directory),
        download_enabled=False, verbose=False)


@registry.tool(name='media.ocr', description='Local image/video-frame OCR with text boxes, confidence and source/timestamp locators. CUDA/MPS first. If GPU is unavailable/fails, ask the user before allow_cpu=true (CPU can be very slow). No model downloads or remote uploads.',
    safety=SafetyLevel.READ_ONLY, tags=('media', 'image', 'video', 'ocr', 'text'), produces=('ocr_text', 'ocr_boxes'), requires=('Pillow', 'easyocr'), cost_hint='high',
    parameters={'type': 'object', 'properties': {**_PATH,
        'languages': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1, 'maxItems': 4, 'default': ['ch_sim', 'en']},
        'allow_cpu': {'type': 'boolean', 'default': False, 'description': 'Set only after telling the user GPU OCR is unavailable/failed and receiving explicit CPU consent.'},
        'start_seconds': {'type': 'number', 'minimum': 0, 'default': 0},
        'interval_seconds': {'type': 'number', 'minimum': 0.1, 'maximum': 3600, 'default': 5},
        'frame_count': {'type': 'integer', 'minimum': 1, 'maximum': 8, 'default': 1},
        'crop_box': _CROP,
        'max_dimension': {'type': 'integer', 'minimum': 128, 'maximum': 4096, 'default': 2560},
        'result_limit': {'type': 'integer', 'minimum': 1, 'maximum': 2000, 'default': 500}}, 'required': ['path']})
def media_ocr(path: str, languages: list[str] | None = None, allow_cpu: bool = False,
              start_seconds: float = 0, interval_seconds: float = 5, frame_count: int = 1,
              max_dimension: int = 2560, result_limit: int = 500, crop_box: list[int] | None = None) -> Observation:
    facts: dict[str, Any] = {'path': path, 'content_examined': False, 'cpu_authorized': allow_cpu,
        'rows': [], 'frames_examined': [], 'text': ''}
    reader, device, failure = _prepare_ocr(facts, languages, allow_cpu, 'media.ocr')
    if failure is not None:
        return failure
    return _recognize_media(path, reader, device, facts, start_seconds, interval_seconds,
                            frame_count, max_dimension, result_limit, crop_box)


def _prepare_ocr(facts: dict[str, Any], languages: list[str] | None, allow_cpu: bool, tool: str):
    device = None
    try:
        device = 'cpu' if allow_cpu else _gpu_device()
        if device is None and not allow_cpu:
            facts.update(reason_code='cpu_consent_required', gpu_available=False,
                required_action='GPU OCR is unavailable. Tell the user CPU OCR may be very slow and ask whether to proceed. No CPU OCR was started.')
            return None, None, Observation(tool, Status.BLOCKED, 'GPU unavailable; CPU OCR needs user consent', facts=facts)
        device = device or 'cpu'
        facts['device'] = device
        reader = _ocr_reader(languages or ['ch_sim', 'en'], device)
    except ImportError as exc:
        facts.update(reason_code='ocr_dependency_missing', required_action='Install dftk[ocr] and provision local EasyOCR weights. No inference was started.')
        return None, device, Observation(tool, Status.UNSUPPORTED, 'Local OCR backend is unavailable', facts=facts, errors=[str(exc)])
    except Exception as exc:
        facts.update(reason_code='gpu_ocr_unavailable' if device != 'cpu' else 'ocr_backend_unavailable',
                     required_action='Check local OCR weights/device. No automatic CPU fallback. Ask the user before CPU execution.')
        return None, device, Observation(tool, Status.UNSUPPORTED, 'OCR could not initialise', facts=facts, errors=[str(exc)])
    return reader, device, None


def _recognize_media(path: str, reader, device: str, facts: dict[str, Any], start_seconds: float,
                     interval_seconds: float, frame_count: int, max_dimension: int,
                     result_limit: int, crop_box: list[int] | None = None) -> Observation:
    p = Path(path)
    try:
        _, category = _kind(p)
        if category == 'video' and crop_box is not None:
            raise ValueError('crop_box requires a still image; video OCR coordinates refer to decoded frames')
    except (OSError, ValueError) as exc:
        facts.update(reason_code='media_decode_failed', required_action='Inspect the source format before another inference attempt')
        return Observation('media.ocr', Status.ERROR, 'Cannot open media source', facts=facts, errors=[str(exc)])
    warnings, errors, evidence = [], [], []
    count = frame_count if category == 'video' else 1
    for index in range(count):
        timestamp = start_seconds + index * interval_seconds if category == 'video' else None
        stage = 'decode'
        try:
            raw = _image_bytes(p, category, timestamp or 0, max_dimension)
            with _open_image(raw) as decoded:
                original_size = list(decoded.size)
                image, region = _image_region(decoded, crop_box)
            with image:
                image.thumbnail((max_dimension, max_dimension))
                import numpy as np
                stage = 'inference'
                rows = reader.readtext(np.asarray(image), detail=1, paragraph=False, batch_size=1, workers=0)
                facts['frames_examined'].append({'timestamp_seconds': timestamp,
                    'original_size': original_size if category != 'video' else None, 'decoded_frame_size': original_size,
                    'processed_size': list(image.size), 'crop_box': region,
                    'box_coordinates': 'processed pixels after EXIF orientation and optional crop'})
                processed_width, processed_height = image.size
            for box, text, confidence in rows:
                if len(facts['rows']) >= result_limit:
                    warnings.append('OCR result limit reached; additional recognised text was omitted'); break
                row = {'text': str(text), 'confidence': float(confidence),
                       'box': [[float(x), float(y)] for x, y in box], 'timestamp_seconds': timestamp,
                       'source_box': [[region[0] + float(x) * (region[2] - region[0]) / processed_width,
                                       region[1] + float(y) * (region[3] - region[1]) / processed_height] for x, y in box],
                       'source_box_space': 'exif_oriented_image' if category != 'video' else 'decoded_scaled_video_frame'}
                facts['rows'].append(row)
                evidence.append(Evidence(path, 'ocr_text', row, locator=f"frame:{index};box:{len(facts['rows'])-1}",
                    method=f'EasyOCR:{device}', confidence=float(confidence), note='OCR transcription needs visual/source verification'))
            if len(facts['rows']) >= result_limit:
                break
        except Exception as exc:
            errors.append(f'{type(exc).__name__}: {exc}')
            facts.update(reason_code='media_decode_failed' if stage == 'decode' else 'gpu_ocr_failed' if device != 'cpu' else 'ocr_failed',
                         required_action='Inspect the file format/decoder before another inference attempt.' if stage == 'decode' else 'GPU OCR failed. No automatic CPU fallback; ask before CPU execution.' if device != 'cpu' else 'Inspect CPU/backend failure before retrying.')
            break
    facts.update(content_examined=bool(facts['frames_examined']), text='\n'.join(row['text'] for row in facts['rows']),
                 scope='Sampled frames only; OCR does not examine audio or establish absence of text in unsampled content' if category == 'video' else 'OCR of a bounded, possibly resized first frame or specified crop; zero recognised text does not mean no text exists')
    if not facts['rows']:
        warnings.append('No text recovered; this is not evidence of absence')
    status = Status.ERROR if errors and not facts['frames_examined'] else Status.PARTIAL if errors or warnings else Status.OK
    return Observation('media.ocr', status, f"Recovered {len(facts['rows'])} OCR text box(es) on {device}", facts=facts,
        evidence=evidence, warnings=warnings, errors=errors, meta={'source_sha256': sha256_file(p)})


@registry.tool(name='media.ocr_batch', description='GPU-first local OCR over up to 32 still images using one model initialisation. Returns separate file outcomes and source-linked text boxes. No visual model disclosure; CPU requires explicit user consent. A GPU inference failure stops the batch without CPU fallback.',
    tags=('media', 'image', 'ocr', 'batch', 'text'), produces=('ocr_text', 'ocr_boxes', 'batch_outcomes'), cost_hint='high',
    requires=('Pillow', 'easyocr'), path_roles={'paths': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {
        'paths': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1, 'maxItems': 32},
        'languages': {'type': 'array', 'items': {'type': 'string'}, 'minItems': 1, 'maxItems': 4, 'default': ['ch_sim', 'en']},
        'allow_cpu': {'type': 'boolean', 'default': False, 'description': 'Only after explicit user consent to slow CPU OCR; never automatically enabled.'},
        'max_dimension': {'type': 'integer', 'minimum': 128, 'maximum': 4096, 'default': 2560},
        'result_limit': {'type': 'integer', 'minimum': 1, 'maximum': 2000, 'default': 1000},
        'time_budget_seconds': {'type': 'number', 'minimum': 1, 'maximum': 120, 'default': 90,
            'description': 'Cooperative budget checked between images, including model initialisation; completed results are returned before continuing unattempted inputs.'}}, 'required': ['paths']})
def media_ocr_batch(paths: list[str], languages: list[str] | None = None, allow_cpu: bool = False,
                    max_dimension: int = 2560, result_limit: int = 1000, time_budget_seconds: float = 90) -> Observation:
    started = _monotonic()
    facts: dict[str, Any] = {'paths': paths, 'cpu_authorized': allow_cpu, 'content_examined': False,
        'files': [], 'rows': [], 'text': '', 'scope': 'first-frame still-image OCR only; no pixels sent to the host model'}
    reader, device, failure = _prepare_ocr(facts, languages, allow_cpu, 'media.ocr_batch')
    if failure is not None:
        failure.facts.update(files=[{'path': path, 'status': 'not_attempted', 'row_count': 0,
            'reason_code': failure.facts.get('reason_code', 'ocr_initialisation_failed')} for path in paths],
            remaining_paths=list(paths), elapsed_seconds=round(_monotonic() - started, 3))
        return failure
    evidence, errors, warnings, sources = [], [], [], []
    stopped = None
    for path in paths:
        if not stopped and _monotonic() - started >= time_budget_seconds:
            stopped = 'time_budget_exhausted'
        if stopped or len(facts['rows']) >= result_limit:
            facts['files'].append({'path': path, 'status': 'not_attempted', 'reason_code': stopped or 'result_limit_reached', 'row_count': 0})
            continue
        try:
            _, category = _kind(Path(path))
            if category != 'image':
                raise ValueError('Batch accepts still images only; select timestamped video OCR separately')
            child = _recognize_media(path, reader, device, {'path': path, 'cpu_authorized': allow_cpu,
                'rows': [], 'frames_examined': [], 'text': ''}, 0, 5, 1, max_dimension, result_limit - len(facts['rows']))
        except (OSError, ValueError) as exc:
            child = Observation('media.ocr', Status.ERROR, 'Cannot open batch image', errors=[str(exc)], facts={'reason_code': 'media_decode_failed', 'rows': [], 'frames_examined': []})
        digest = child.meta.get('source_sha256', '')
        sources.append({'path': path, 'source_sha256': digest})
        facts['files'].append({'path': path, 'status': child.status.value,
            'content_examined': bool(child.facts.get('content_examined')), 'row_count': len(child.facts['rows']),
            'reason_code': child.facts.get('reason_code'), 'frames_examined': child.facts.get('frames_examined', []),
            'errors': child.errors, 'source_sha256': digest})
        for row in child.facts['rows']:
            facts['rows'].append({**row, 'source': path, 'source_sha256': digest})
        for item in child.evidence:
            item.source_sha256 = digest
            evidence.append(item)
        warnings.extend(f'{path}: {warning}' for warning in child.warnings)
        errors.extend(f'{path}: {error}' for error in child.errors)
        if child.facts.get('reason_code') in {'gpu_ocr_failed', 'ocr_failed'}:
            stopped = child.facts['reason_code']
            facts.update(reason_code=stopped, required_action='GPU inference failed; batch stopped. No automatic CPU fallback. Ask the user before a CPU run.' if stopped == 'gpu_ocr_failed' else 'CPU inference failed; batch stopped. Inspect the backend before retrying.')
    if stopped == 'time_budget_exhausted':
        facts.update(reason_code=stopped, required_action='Completed results are retained; continue only remaining_paths in a new bounded batch.')
    facts.update(text='\n'.join(row['text'] for row in facts['rows']), content_examined=any(item.get('content_examined') for item in facts['files']),
        elapsed_seconds=round(_monotonic() - started, 3), time_budget_seconds=time_budget_seconds,
        remaining_paths=[item['path'] for item in facts['files'] if item['status'] == 'not_attempted'])
    if any(item['status'] == 'not_attempted' for item in facts['files']):
        warnings.append('Some batch inputs were not attempted; inspect per-file outcomes')
    status = Status.ERROR if errors and not facts['content_examined'] else Status.PARTIAL if errors or warnings else Status.OK
    return Observation('media.ocr_batch', status, f"Recovered {len(facts['rows'])} OCR boxes from {len(paths)} listed image(s) on {device}",
        facts=facts, evidence=evidence, errors=errors, warnings=warnings, meta={'sources': sources})
