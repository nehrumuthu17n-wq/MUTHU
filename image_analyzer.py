"""
image_analyzer.py
------------------
Lightweight, dependency-free (beyond Pillow/NumPy) heuristics for
spotting possibly manipulated or AI-generated images:

  1. Error Level Analysis (ELA)   -> detects local re-compression
     inconsistencies typical of photo edits/splices.
  2. EXIF metadata inspection      -> missing/edited-by metadata,
     software tags left behind by editing tools.
  3. Noise-pattern uniformity      -> AI-generated / heavily smoothed
     images often show unnaturally uniform noise.

This is a *preliminary* screening tool, not a forensic-grade detector.
"""

import io
import os
import tempfile
from datetime import datetime, timezone
from PIL import Image, ImageChops, ExifTags
import numpy as np

EDITING_SOFTWARE_HINTS = [
    "photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva",
    "facetune", "midjourney", "dall", "stable diffusion", "affinity"
]

_NUDE_DETECTOR = None
_NUDE_DETECTOR_LOAD_ERROR = None


def _error_level_analysis(img: Image.Image, quality: int = 90):
    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=quality)
    buf.seek(0)
    resaved = Image.open(buf)

    diff = ImageChops.difference(img.convert("RGB"), resaved)
    diff_np = np.array(diff).astype(np.float32)

    mean_diff = float(diff_np.mean())
    max_diff = float(diff_np.max())
    # Std of block-wise means highlights localized (patchy) edits
    h, w, _ = diff_np.shape
    block = 16
    block_means = []
    for y in range(0, h - block, block):
        for x in range(0, w - block, block):
            block_means.append(diff_np[y:y + block, x:x + block].mean())
    block_std = float(np.std(block_means)) if block_means else 0.0

    return {
        "mean_diff": round(mean_diff, 3),
        "max_diff": round(max_diff, 3),
        "block_std": round(block_std, 3),
    }


def _parse_exif_datetime(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    value = str(value).strip()
    if not value:
        return None

    candidates = [
        "%Y:%m:%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y:%m:%d",
    ]
    for fmt in candidates:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _exif_summary(img: Image.Image):
    try:
        exif_raw = img._getexif()
    except Exception:
        exif_raw = None

    if not exif_raw:
        return {"has_exif": False, "software": None, "tags": {}, "capture_datetime": None, "age_days": None}

    tags = {}
    for tag_id, value in exif_raw.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        try:
            tags[tag_name] = str(value)
        except Exception:
            continue

    software = tags.get("Software", "")
    capture_datetime = None
    for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime", "ModifyDate"):
        parsed = _parse_exif_datetime(tags.get(key))
        if parsed:
            capture_datetime = parsed
            break

    age_days = None
    if capture_datetime is not None:
        now_utc = datetime.now(timezone.utc)
        if capture_datetime.tzinfo is None:
            age_seconds = (now_utc - capture_datetime.replace(tzinfo=timezone.utc)).total_seconds()
        else:
            age_seconds = (now_utc - capture_datetime.astimezone(timezone.utc)).total_seconds()
        age_days = max(0.0, age_seconds / 86400.0)

    return {
        "has_exif": True,
        "software": software,
        "tags": tags,
        "capture_datetime": capture_datetime.isoformat() if capture_datetime else None,
        "age_days": round(age_days, 2) if age_days is not None else None,
    }


def _noise_uniformity(img: Image.Image):
    gray = np.array(img.convert("L")).astype(np.float32)
    # Laplacian-like high-frequency estimate via simple kernel convolution
    kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
    h, w = gray.shape
    if h < 3 or w < 3:
        return {"noise_std": 0.0, "gray_std": 0.0, "laplacian_std": 0.0}

    lap = None
    try:
        from scipy import signal  # optional; fallback below if unavailable
        lap = signal.convolve2d(gray, kernel, mode="valid")
    except Exception:
        lap = None

    if lap is None:
        # Manual convolution fallback (small images only)
        lap = (
            gray[0:-2, 1:-1] + gray[2:, 1:-1] + gray[1:-1, 0:-2] +
            gray[1:-1, 2:] - 4 * gray[1:-1, 1:-1]
        )

    gray_std = float(np.std(gray))
    laplacian_std = float(np.std(lap))
    return {
        "noise_std": round(float(np.std(lap)), 3),
        "gray_std": round(gray_std, 3),
        "laplacian_std": round(laplacian_std, 3),
    }


def _safety_flags(img: Image.Image):
    global _NUDE_DETECTOR, _NUDE_DETECTOR_LOAD_ERROR

    if _NUDE_DETECTOR is None and _NUDE_DETECTOR_LOAD_ERROR is None:
        try:
            from nudenet import NudeDetector
            _NUDE_DETECTOR = NudeDetector()
        except Exception as exc:
            _NUDE_DETECTOR_LOAD_ERROR = str(exc)

    if _NUDE_DETECTOR is None:
        return {
            "nudity_risk": False,
            "explicit_content": False,
            "synthetic_person_risk": False,
            "nsfw_check": "not_assessed",
            "detector": "NudeNet unavailable; no color-based guess was made",
        }

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temporary_file:
            temporary_path = temporary_file.name
        img.convert("RGB").save(temporary_path, format="JPEG", quality=95)
        detections = _NUDE_DETECTOR.detect(temporary_path) or []
        explicit_labels = {
            "EXPOSED_ANUS",
            "EXPOSED_BREAST_F",
            "EXPOSED_BUTTOCKS",
            "EXPOSED_GENITALIA_F",
            "EXPOSED_GENITALIA_M",
            "EXPOSED_BREAST_M",
        }
        explicit_detections = [
            detection for detection in detections
            if detection.get("class") in explicit_labels and float(detection.get("score", 0)) >= 0.70
        ]
        return {
            "nudity_risk": bool(explicit_detections),
            "explicit_content": bool(explicit_detections),
            "synthetic_person_risk": False,
            "nsfw_check": "potentially_explicit" if explicit_detections else "clear",
            "detector": "NudeNet",
            "detections": [
                {"class": item.get("class"), "score": round(float(item.get("score", 0)), 3)}
                for item in explicit_detections
            ],
        }
    except Exception as exc:
        return {
            "nudity_risk": False,
            "explicit_content": False,
            "synthetic_person_risk": False,
            "nsfw_check": "not_assessed",
            "detector": f"NudeNet error: {exc}",
        }
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def analyze_image(image_bytes: bytes) -> dict:
    findings = []
    penalty = 0

    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
    except Exception:
        return {
            "score": 30.0,
            "findings": [{
                "severity": "medium",
                "message": "The file could not be read as a valid image."
            }],
            "details": {}
        }

    width, height = img.size
    fmt = img.format
    safety = _safety_flags(img)

    # 1. ELA ---------------------------------------------------------------
    ela = _error_level_analysis(img)
    if ela["block_std"] > 9.0:
        penalty += 24
        findings.append({
            "severity": "high",
            "message": "Error Level Analysis shows strong uneven compression across the image, "
                       "which is a common sign of localized editing, splicing, or manipulation."
        })
    elif ela["block_std"] > 5.5:
        penalty += 12
        findings.append({
            "severity": "medium",
            "message": "Error Level Analysis shows compression inconsistencies that could indicate light editing or a composite image."
        })
    else:
        findings.append({
            "severity": "info",
            "message": "Error Level Analysis did not find strong evidence of localized editing."
        })

    # 2. EXIF metadata -------------------------------------------------------
    exif = _exif_summary(img)
    if fmt == "JPEG" and not exif["has_exif"]:
        findings.append({
            "severity": "info",
            "message": "No EXIF capture metadata was found. This alone does not prove the image was edited; "
                       "screenshots, reposts, and compressed uploads often lose metadata while still being authentic."
        })
    elif exif["age_days"] is not None:
        if exif["age_days"] <= 2:
            findings.append({
                "severity": "info",
                "message": f"The image EXIF date shows it was captured about {exif['age_days']:.1f} days ago. "
                           "A very recent capture is normal and should not be treated as evidence of tampering by itself."
            })
        else:
            findings.append({
                "severity": "info",
                "message": f"The image EXIF date indicates it was captured about {exif['age_days']:.1f} days ago. "
                           "This age is consistent with a previously created image and is not an automatic sign of manipulation."
            })
    if exif["software"]:
        sw_lower = exif["software"].lower()
        if any(hint in sw_lower for hint in EDITING_SOFTWARE_HINTS):
            penalty += 14
            findings.append({
                "severity": "medium",
                "message": f"EXIF metadata shows the image was processed with '{exif['software']}', which is consistent with editing or AI-assisted generation."
            })

    # 3. Noise / texture quality (AI-generation signal) ------------------------
    noise = _noise_uniformity(img)
    if noise["noise_std"] < 2.5:
        penalty += 15
        findings.append({
            "severity": "medium",
            "message": "The image shows unusually smooth or uniform texture/noise patterns, which can indicate AI generation or heavy filtering."
        })
    elif noise["gray_std"] < 12 and (width * height) < 180000:
        penalty += 10
        findings.append({
            "severity": "low",
            "message": "The image is very flat and low-texture, which reduces confidence in its authenticity and makes it easier to fake."
        })

    # 4. Tiny / low-detail images ------------------------------------------------
    if width < 100 or height < 100:
        penalty += 12
        findings.append({
            "severity": "low",
            "message": "The image resolution is very low, which makes the trust assessment less reliable and increases the chance of low-effort manipulation."
        })
    elif (width * height) < 150000 and noise["gray_std"] < 20:
        penalty += 8
        findings.append({
            "severity": "low",
            "message": "The image is small and low-detail, which limits forensic confidence and can hide editing."
        })

    # 5. Hard block for obvious low-quality synthetic cases ----------------------
    if noise["noise_std"] < 1.8 and (width * height) < 250000:
        penalty += 15
        findings.append({
            "severity": "high",
            "message": "The combination of low texture and tiny dimensions is a strong sign of an artificially generated or heavily smoothed image."
        })

    # 6. Separate safety checks for explicit / synthetic-person content ----------
    if safety["explicit_content"] and safety["nudity_risk"]:
        penalty += 40
        findings.append({
            "severity": "medium",
            "message": "Separate content-safety check: this image shows a strong nudity/explicit-content risk and should be reviewed before sharing.",
            "category": "content_safety"
        })
    elif safety["synthetic_person_risk"]:
        findings.append({
            "severity": "low",
            "message": "Separate content-safety check: this image may contain a fake-person or deepfake-style face and should be reviewed carefully.",
            "category": "content_safety"
        })

    penalty = min(penalty, 100)
    score = max(0, 100 - penalty)
    has_strong_risk_signal = (
        safety["explicit_content"] or
        bool(exif["software"]) or
        (noise["noise_std"] < 1.8 and (width * height) < 250000)
    )
    if not has_strong_risk_signal and score < 70:
        score = 70.0
    if safety["explicit_content"] and safety["nudity_risk"] and score > 50:
        score = 50.0
    if score >= 80:
        verdict = "Likely original"
    elif score < 50:
        verdict = "Likely manipulated or AI-generated"
    else:
        verdict = "Needs verification"

    return {
        "score": round(score, 1),
        "findings": findings,
        "details": {
            "format": fmt,
            "dimensions": f"{width}x{height}",
            "exif": exif,
            "ela": ela,
            "noise": noise,
            "safety": safety,
            "verdict": verdict,
        }
    }
