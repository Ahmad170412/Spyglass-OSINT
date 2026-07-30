import os
import re
import json
import subprocess
from datetime import datetime

from .utils import _run, _check_tool, _EXIFTOOL


def extract(path):
    """Extract metadata from a file. Returns a structured dict."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}

    result = _file_info(path)

    if _EXIFTOOL:
        meta = _exiftool_extract(path)
        if meta:
            result.update(meta)
            return result

    # No exiftool — try Python fallbacks per type
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg", ".jpeg", ".tiff", ".tif", ".png", ".webp"):
        img = _pillow_exif(path)
        if img:
            result.update(img)
    elif ext == ".pdf":
        pdf = _pdf_meta(path)
        if pdf:
            result.update(pdf)
    elif ext in (".docx", ".xlsx", ".pptx"):
        ooxml = _ooxml_meta(path)
        if ooxml:
            result.update(ooxml)

    return result


def _file_info(path):
    st = os.stat(path)
    return {
        "file_name": os.path.basename(path),
        "file_size": _human_size(st.st_size),
        "file_type": _mime_type(path),
        "created": datetime.fromtimestamp(st.st_birthtime).isoformat() if hasattr(st, "st_birthtime") else "N/A",
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
    }


def _exiftool_extract(path):
    """Full metadata via exiftool — the gold standard."""
    try:
        r = subprocess.run(
            [_EXIFTOOL, "-j", "-G", path],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(r.stdout.strip())
        if isinstance(data, list) and data:
            return _clean_exiftool(data[0])
    except Exception:
        pass
    return {}


_CURATED = {
    # File
    "FileSize", "FileType", "FileTypeExtension", "MIMEType",
    "ImageWidth", "ImageHeight", "Megapixels", "Duration",
    # Image
    "Make", "Model", "Software", "Orientation", "XResolution", "YResolution",
    "ISO", "Aperture", "FNumber", "ExposureTime", "FocalLength",
    "Flash", "WhiteBalance", "ColorSpace",
    # Timestamps
    "DateTimeOriginal", "CreateDate", "ModifyDate", "DateCreated",
    "ProfileDateTime", "CreationDate",
    # GPS
    "GPSLatitude", "GPSLatitudeRef", "GPSLongitude", "GPSLongitudeRef",
    "GPSAltitude", "GPSAltitudeRef", "GPSPosition", "GPSDateTime",
    # Documents
    "Author", "Creator", "Producer", "Title", "Subject",
    "Description", "Keywords", "LastModifiedBy", "RevisionNumber",
    "Company", "Manager", "Category", "Language", "Pages",
    # Audio/Video
    "Artist", "Album", "Title", "Track", "Genre", "Duration",
    "SampleRate", "Channels", "AudioBitrate",
    # Network / forensic
    "UserComment", "Warning",
}

_IGNORE_VALUES = {"N/A", "-", "unknown", "Unspecified", "", "none", "None"}


def _clean_exiftool(raw):
    """Return only curated fields + GPS, with clean names."""
    out = {}
    gps = {}

    for key, val in raw.items():
        if val is None or val == "":
            continue
        s = str(val).strip()
        if s in _IGNORE_VALUES:
            continue
        short = key.split(":")[-1] if ":" in key else key

        # Collect GPS subfields separately
        if short.startswith("GPS") and short != "GPSPosition":
            gps[short] = s
            continue

        if short not in _CURATED:
            continue

        out[short] = s

    if gps:
        out["GPS"] = gps
    return out


def _pillow_exif(path):
    """Image EXIF via Pillow."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return {}

    try:
        img = Image.open(path)
        exif = img._getexif()
        if not exif:
            return {}
        out = {}
        gps = {}
        for tag_id, val in exif.items():
            name = TAGS.get(tag_id, tag_id)
            if isinstance(val, bytes):
                try:
                    val = val.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
            if name == "GPSInfo":
                for k, v in val.items():
                    gps_tag = {0: "GPSLatitudeRef", 1: "GPSLatitude",
                               2: "GPSLongitudeRef", 3: "GPSLongitude",
                               4: "GPSAltitudeRef", 5: "GPSAltitude"}.get(k, str(k))
                    gps[gps_tag] = v
                continue
            if isinstance(val, (int, float)):
                out[name] = val
            else:
                s = str(val).strip()
                if s and s != "N/A":
                    out[name] = s
        if gps:
            out["GPS"] = gps
        return out
    except Exception:
        return {}


def _pdf_meta(path):
    """PDF metadata via PyPDF2."""
    try:
        import PyPDF2
    except ImportError:
        try:
            import pdfminer
            return _pdfminer_meta(path)
        except ImportError:
            return {}
    try:
        with open(path, "rb") as f:
            r = PyPDF2.PdfReader(f)
            info = r.metadata
            if info:
                return {k: str(v) for k, v in info.items() if v}
    except Exception:
        pass
    return {}


def _pdfminer_meta(path):
    try:
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdfdocument import PDFDocument
        with open(path, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)
            return {k: str(v) for k, v in (doc.info[0] if doc.info else {}).items() if v}
    except Exception:
        return {}


def _ooxml_meta(path):
    """Office Open XML metadata (docx/xlsx/pptx) via python-docx/openpyxl."""
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".docx":
            import docx
            d = docx.Document(path)
            p = d.core_properties
        elif ext == ".xlsx":
            import openpyxl
            wb = openpyxl.load_workbook(path)
            p = wb.properties
        else:
            return {}
        out = {}
        for attr in ("author", "category", "comments", "content_status", "created",
                      "creator", "description", "identifier", "keywords", "language",
                      "last_modified_by", "last_printed", "modified", "revision",
                      "subject", "title", "version"):
            val = getattr(p, attr, None)
            if val:
                out[attr.replace("_", " ").title()] = str(val)
        return out
    except Exception:
        return {}


def _human_size(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _mime_type(path):
    ext = os.path.splitext(path)[1].lower()
    return {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
        ".gif": "image/gif", ".webp": "image/webp", ".tiff": "image/tiff",
        ".pdf": "application/pdf", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".mp3": "audio/mpeg", ".mp4": "video/mp4",
    }.get(ext, "application/octet-stream")
