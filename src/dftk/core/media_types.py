"""Cheap discovery only: no pixel decoding, OCR or model transmission."""
from pathlib import Path

IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tif', '.tiff', '.webp', '.heic', '.heif', '.avif'}
VIDEO_EXTENSIONS = {'.mp4', '.mov', '.m4v', '.avi', '.mkv', '.webm', '.mpeg', '.mpg', '.wmv', '.flv', '.3gp'}


def media_type(kind: str, filename: str = '') -> str | None:
    if kind in {'png', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'heic', 'avif'}:
        return 'image'
    if kind in {'mp4', 'mov', 'avi', 'matroska', 'webm', 'mpeg', 'wmv', 'flv'}:
        return 'video'
    # Extensions are hints, never a verified classification.
    suffix = Path(filename).suffix.lower()
    return 'image' if suffix in IMAGE_EXTENSIONS else 'video' if suffix in VIDEO_EXTENSIONS else None


def media_signature(head: bytes) -> str | None:
    for sig, kind in [(b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpeg'),
                      (b'GIF87a', 'gif'), (b'GIF89a', 'gif'), (b'BM', 'bmp'),
                      (b'II*\0', 'tiff'), (b'MM\0*', 'tiff'),
                      (b'\x1aE\xdf\xa3', 'matroska'), (b'FLV', 'flv')]:
        if head.startswith(sig):
            return kind
    if head.startswith(b'RIFF') and len(head) >= 12:
        return {b'WEBP': 'webp', b'AVI ': 'avi'}.get(head[8:12])
    if len(head) >= 12 and head[4:8] == b'ftyp':
        brand = head[8:12]
        if brand in {b'avif', b'avis'}:
            return 'avif'
        if brand in {b'heic', b'heix', b'hevc', b'hevx', b'mif1', b'msf1'}:
            return 'heic'
        return 'mov' if brand == b'qt  ' else 'mp4'
    return None
