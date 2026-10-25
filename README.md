# Digital Trust Score (DTS)

A single, user-friendly platform for **preliminary digital risk assessment** —
check URLs, emails, QR codes, and images for common phishing, spoofing, and
manipulation red flags, and get back a 0–100 **Trust Score** with plain-language
reasons and recommendations.

This is a working prototype built to match the DTS problem statement: one
unified tool instead of separate apps for URL checking, email screening, QR
scanning, and image forensics.

---

## How it works

| Content type | Techniques used |
|---|---|
| **URL** | Structural heuristics: HTTPS usage, IP-literal hosts, suspicious TLDs, URL shorteners, `@` tricks, excessive subdomains/hyphens, urgency keywords, **typosquatting/brand-impersonation detection** (Levenshtein distance + leetspeak normalization), punycode/homograph detection, subdomain entropy |
| **Email** | NLP-style pattern matching: display-name vs. sender-domain spoofing, free-mail-domain-posing-as-brand, urgency/pressure language, generic greetings, requests for sensitive data, plus automatic extraction and scoring of every link in the message body |
| **QR Code** | Computer vision decoding via OpenCV's `QRCodeDetector` (no external binaries needed), then the decoded payload is routed through the URL analyzer if it's a link |
| **Image** | Computer-vision forensics: **Error Level Analysis (ELA)** for spliced/edited regions, EXIF metadata inspection (missing metadata, known editing/AI-generation software tags), and noise-uniformity analysis (a signal for AI-generated or heavily smoothed images) |

Every analyzer returns a `score` (0–100) plus a list of `findings`
(`severity`: `high` / `medium` / `low` / `info`). The `scoring.py` module
turns that into the final Trust Score, a risk band (Trusted → Critical
Risk), and tailored recommendations.

> **Note:** This heuristic engine runs fully **offline** — no external APIs
> or ML model downloads are required, so it works in network-restricted
> environments. `url_analyzer.py` has an `enrich_with_external_api()` stub
> ready for wiring up real threat-intel feeds (Google Safe Browsing,
> VirusTotal, PhishTank, etc.) if/when you have API keys and network access.
> Likewise, the image/QR analyzers can be upgraded to call cloud vision or
> deepfake-detection APIs — the current implementation uses local
> CV heuristics (OpenCV/Pillow/NumPy) so the whole system runs standalone.

---

## Project structure

```
digital-trust-score/
├── backend/
│   ├── app.py                  # Flask REST API
│   ├── requirements.txt
│   ├── analyzers/
│   │   ├── url_analyzer.py     # Phishing/malicious URL heuristics
│   │   ├── email_analyzer.py   # Email spoofing/phishing heuristics
│   │   ├── qr_analyzer.py      # QR decode (OpenCV) + URL re-analysis
│   │   └── image_analyzer.py   # ELA, EXIF, noise-based image forensics
│   └── utils/
│       └── scoring.py          # Aggregates findings into final Trust Score
├── frontend/
│   ├── index.html              # Single-page UI (URL / Email / QR / Image tabs)
│   ├── style.css
│   └── script.js
└── README.md
```

---

## Setup & run

Requires Python 3.9+.

```bash
cd digital-trust-score/backend
pip install -r requirements.txt   # (flask-cors is optional; app.py falls back gracefully)
python app.py
```

The server starts on **http://localhost:5000** and serves both the API
and the frontend UI (Flask serves `frontend/index.html` at `/`), so you
can just open that URL in your browser — no separate frontend server or
build step needed.

### API endpoints

```
GET  /api/health
POST /api/analyze/url     { "url": "https://example.com" }
POST /api/analyze/email   { "from": "...", "subject": "...", "body": "..." }
POST /api/analyze/qr      multipart/form-data, field "image"
POST /api/analyze/image   multipart/form-data, field "image"
```

Example:

```bash
curl -X POST http://localhost:5000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure.com/login/verify-account"}'
```

Response shape (same for all content types):

```json
{
  "content_type": "url",
  "trust_score": 55.0,
  "risk_level": "Moderate Risk",
  "risk_color": "#e6a817",
  "reasons": [{"severity": "high", "message": "..."}],
  "recommendations": ["..."],
  "details": {"...": "..."}
}
```

---

## Extending this prototype

- **Real-time threat intel**: plug Google Safe Browsing / VirusTotal / PhishTank
  into `url_analyzer.enrich_with_external_api()`.
- **ML/NLP upgrade**: swap the keyword-based email heuristics for a trained
  phishing-classification model (e.g. a fine-tuned transformer) while keeping
  the same `{score, findings}` contract so `scoring.py` and the frontend don't
  need to change.
- **Deepfake/AI-image detection**: the `image_analyzer.py` noise/ELA heuristics
  are a lightweight stand-in for a dedicated CV model (e.g. a CNN trained on
  real vs. AI-generated images) — same drop-in contract applies.
- **Browser extension**: the REST API is content-type agnostic, so a browser
  extension could call `/api/analyze/url` before a user visits a link, or
  `/api/analyze/email` on webmail content.
- **Auth & rate limiting**: add before any public deployment.

---

## Disclaimer

This tool provides a **preliminary risk indication only**. It is a heuristic
prototype, not a certified security product, and should not replace
official antivirus/anti-phishing software, organizational IT policy, or
your own judgment when handling sensitive links, emails, codes, or images.
