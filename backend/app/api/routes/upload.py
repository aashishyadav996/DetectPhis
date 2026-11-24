"""
Email and file upload analysis Flask Blueprint.

Provides endpoints for:
  - Uploading .eml email files for header/URL extraction
  - Generic file hash and metadata analysis
  - Email address (user@domain.com) investigation
"""
from flask import Blueprint, request, jsonify, abort

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import get_virustotal_evidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.graph.builder import build_threat_graph
from app.modules.risk_engine.engine import assess_risk
from app.modules.email_analysis.parser import analyze_email
from app.modules.email_analysis.investigator import investigate_email_address
from app.modules.file_analysis.scanner import analyze_file

upload_bp = Blueprint("upload", __name__, url_prefix="/api/v1/analyze")


@upload_bp.route("/email", methods=["POST"])
def analyze_email_upload():
    """
    Accepts an uploaded .eml file, extracts headers and embedded URLs,
    and optionally runs the first extracted URL through the full
    multi-signal analysis pipeline.
    """
    if "file" not in request.files:
        abort(400, description="No file selected.")

    file = request.files["file"]
    if not file.filename:
        abort(400, description="No file selected.")

    try:
        content = file.read()
        email_data = analyze_email(content)

        # Auto-analyze the first extracted URL if any exist
        urls = email_data.get("extracted_urls", [])
        if urls:
            try:
                normalized = normalize_url(urls[0])
                features = extract_features(normalized)
                brand_match = detect_brand_impersonation(features.sld, normalized)
                vt_evidence = get_virustotal_evidence(normalized)
                ml_prediction = predict_phishing_probability(features)
                threat_graph = build_threat_graph(features, brand_match)
                assessment = assess_risk(
                    features, brand_match, vt_evidence, ml_prediction, threat_graph
                )

                email_data["url_analysis"] = {
                    "url": urls[0],
                    "normalized_url": normalized,
                    "risk_score": assessment.risk_score,
                    "confidence": assessment.confidence,
                    "classification": assessment.classification,
                    "reasons_increasing": assessment.reasons_increasing,
                    "reasons_decreasing": assessment.reasons_decreasing,
                }
            except (InvalidURLError, Exception):
                # URL analysis failure must not block email header results
                email_data["url_analysis"] = {
                    "url": urls[0],
                    "error": "Could not analyze extracted URL.",
                }

        return jsonify(email_data), 200

    except Exception as exc:
        abort(500, description=f"Failed to analyze email: {exc}")


@upload_bp.route("/file", methods=["POST"])
def analyze_file_upload():
    """
    Accepts an uploaded file, computes cryptographic hashes (MD5, SHA-1,
    SHA-256) and returns basic metadata. VT file lookup integration is
    pending — noted inline as a placeholder.
    """
    if "file" not in request.files:
        abort(400, description="No file selected.")

    file = request.files["file"]
    if not file.filename:
        abort(400, description="No file selected.")

    try:
        content = file.read()
        file_data = analyze_file(content, file.filename)
        return jsonify(file_data), 200

    except Exception as exc:
        abort(500, description=f"Failed to analyze file: {exc}")


@upload_bp.route("/email-address", methods=["POST"])
def analyze_email_address():
    """
    Investigates an email address (user@domain.com) for phishing indicators:
      - Format validation
      - DNS MX / A record checks
      - RDAP domain age & registrar profiling
      - Disposable / free provider detection
      - Suspicious local-part pattern analysis
      - Brand impersonation detection on the domain

    Request body (JSON):
        { "email": "suspect@example.com" }

    Returns a structured risk assessment with score, level, and reasons.
    """
    body = request.get_json(silent=True)
    if not body or not body.get("email"):
        abort(400, description="Missing required field: email")

    email_input = body["email"].strip()
    if len(email_input) > 320:
        abort(400, description="Email address too long (max 320 characters).")

    try:
        result = investigate_email_address(email_input)
        return jsonify(result), 200
    except Exception as exc:
        abort(500, description=f"Email investigation failed: {exc}")

