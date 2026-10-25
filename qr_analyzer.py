"""
qr_analyzer.py
--------------
Decodes a QR code from an uploaded image using OpenCV's built-in
QRCodeDetector (no extra native dependencies like zbar required), then
routes the decoded payload through the appropriate analyzer:
  - If it's a URL -> url_analyzer
  - Otherwise -> returned as raw text with basic content heuristics
"""

import re
import cv2
import numpy as np

from .url_analyzer import analyze_url

URL_LIKE_REGEX = re.compile(r"^[a-zA-Z]+://|^www\.", re.IGNORECASE)
SUSPICIOUS_QR_TEXT = [
    "login", "verify", "secure", "account", "update", "confirm", "claim",
    "invoice", "billing", "urgent", "reward", "gift", "win", "click here",
    "download", "payment", "suspended", "reset your password"
]


def _normalize_qr_payload(data: str) -> str:
    return "".join(ch for ch in data.strip() if ch not in "\r\n\t ").lower()


def _decode_qr(image_bytes: bytes):
    file_bytes = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if img is None:
        return None, None

    detector = cv2.QRCodeDetector()
    height, width = img.shape[:2]
    scale = 2 if max(height, width) < 1600 else 1
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    if scale > 1:
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Phone photos often have uneven lighting or a small, soft QR code.
    variants = [
        img,
        gray,
        cv2.equalizeHist(gray),
        cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
        cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                              cv2.THRESH_BINARY, 31, 5),
    ]

    for variant in variants:
        data, points, _ = detector.detectAndDecode(variant)
        if data:
            return data, points

        # Also handle more than one code in a camera frame.
        try:
            ok, decoded_info, points, _ = detector.detectAndDecodeMulti(variant)
            if ok and decoded_info:
                data = next((value for value in decoded_info if value), "")
                if data:
                    return data, points
        except Exception:
            continue

    return None, None


def analyze_qr(image_bytes: bytes) -> dict:
    data, points = _decode_qr(image_bytes)

    if not data:
        return {
            "score": 40.0,
            "findings": [{
                "severity": "medium",
                "message": "No readable QR code was detected in the image, or it is too damaged/blurred to decode. "
                           "Treat unreadable codes with caution."
            }],
            "details": {"decoded": False, "payload": None},
        }

    result = {
        "details": {"decoded": True, "payload": data}
    }

    normalized = _normalize_qr_payload(data)
    url_candidate = data.strip()
    if URL_LIKE_REGEX.match(url_candidate) or "http" in normalized or "www." in normalized:
        url_result = analyze_url(url_candidate)
        result["score"] = url_result["score"]
        result["findings"] = [
            {"severity": "info", "message": f"The QR code decodes to a URL: {url_candidate}"}
        ] + url_result["findings"]
        result["details"]["type"] = "url"
        result["details"]["url_analysis"] = url_result

        if any(token in normalized for token in ["login", "verify", "secure", "account", "update", "claim", "payment"]):
            result["score"] = max(0, result["score"] - 12)
            result["findings"].append({
                "severity": "medium",
                "message": "The QR payload looks like a credential or payment page rather than a normal informational link, which is common in phishing QR codes."
            })
    else:
        # Non-URL payload (plain text, wifi config, vCard, etc.)
        findings = [{
            "severity": "info",
            "message": "The QR code contains non-URL text/data rather than a web link."
        }]
        score = 75.0
        lowered = data.lower()
        if any(token in lowered for token in SUSPICIOUS_QR_TEXT):
            score -= 25
            findings.append({
                "severity": "medium",
                "message": "The QR text contains phishing-style language such as login, verify, or payment requests, which is a common lure in fake QR codes."
            })
        if "bitcoin:" in lowered or "wallet" in lowered:
            score -= 20
            findings.append({
                "severity": "medium",
                "message": "The QR code appears to reference a cryptocurrency wallet/address; verify the recipient carefully before sending funds."
            })
        if "http" in lowered or "www." in lowered:
            score -= 15
            findings.append({
                "severity": "medium",
                "message": "The QR payload contains URL-like content but not a clean, trustworthy destination; verify the address before opening it."
            })
        result["score"] = max(0, score)
        result["findings"] = findings
        result["details"]["type"] = "text"

    return result
