"""
app.py
------
Digital Trust Score (DTS) backend API.

Endpoints:
  POST /api/analyze/url    { "url": "..." }
  POST /api/analyze/email  { "from": "...", "subject": "...", "body": "..." }
  POST /api/analyze/qr     multipart/form-data, field "image"
  POST /api/analyze/image  multipart/form-data, field "image"
  GET  /api/health

Run:
  cd backend
  pip install -r requirements.txt
  python app.py
  # Server runs on http://localhost:5000
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory

from analyzers.url_analyzer import analyze_url
from analyzers.email_analyzer import analyze_email
from analyzers.qr_analyzer import analyze_qr
from analyzers.image_analyzer import analyze_image
from utils.scoring import finalize

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# The frontend is served by this same Flask app (see index() below), so
# cross-origin requests aren't required for normal use. We still add
# permissive CORS headers here (without requiring the flask-cors package)
# in case the frontend is ever hosted separately from the API.
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    @app.after_request
    def _add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

MAX_UPLOAD_MB = 8
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "Digital Trust Score API"})


@app.route("/api/analyze/url", methods=["POST"])
def api_analyze_url():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' field."}), 400

    result = analyze_url(url)
    return jsonify(finalize("url", result))


@app.route("/api/analyze/email", methods=["POST"])
def api_analyze_email():
    payload = request.get_json(silent=True) or {}
    from_header = payload.get("from", "")
    subject = payload.get("subject", "")
    body = payload.get("body", "")

    if not (from_header or subject or body):
        return jsonify({"error": "Provide at least one of 'from', 'subject', or 'body'."}), 400

    result = analyze_email(from_header, subject, body)
    return jsonify(finalize("email", result))


@app.route("/api/analyze/qr", methods=["POST"])
def api_analyze_qr():
    if "image" not in request.files:
        return jsonify({"error": "Missing 'image' file field."}), 400
    file = request.files["image"]
    image_bytes = file.read()
    if not image_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    result = analyze_qr(image_bytes)
    return jsonify(finalize("qr", result))


@app.route("/api/analyze/image", methods=["POST"])
def api_analyze_image():
    if "image" not in request.files:
        return jsonify({"error": "Missing 'image' file field."}), 400
    file = request.files["image"]
    image_bytes = file.read()
    if not image_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    result = analyze_image(image_bytes)
    return jsonify(finalize("image", result))


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": f"File too large. Max size is {MAX_UPLOAD_MB}MB."}), 413


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
