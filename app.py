"""
PhishTrace AI — Flask Full-Stack Application.
Serves the HTML5/CSS/JS frontend dashboard and the complete multi-signal forensic API.
"""
import os
import ipaddress
import secrets
from flask import Flask, render_template, request, jsonify, Response
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from dotenv import load_dotenv

load_dotenv()

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import get_virustotal_evidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.graph.builder import build_threat_graph
from app.modules.risk_engine.engine import assess_risk
from app.modules.adversarial.evaluator import evaluate_adversarial_resilience
from app.database.connection import init_db
from app.database.repository import (
    save_scan_record,
    get_recent_scans,
    get_scan_by_id,
    clear_all_scans,
)
from app.modules.reports.generator import (
    generate_investigation_report_html,
    generate_investigation_report_json,
)
from app.modules.email_analysis.parser import analyze_email
from app.modules.email_analysis.investigator import investigate_email_address
from app.modules.file_analysis.scanner import analyze_file

# Initialize database tables
try:
    init_db()
except Exception as exc:
    print(f"Database initialization warning: {exc}")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH", str(10 * 1024 * 1024))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("APP_ENV", "development").lower() == "production",
    JSON_SORT_KEYS=False,
)

# This build has no user-account system. Keep it local-only by default and
# reject requests from non-loopback clients rather than exposing private scan
# history and destructive history controls on a network interface.
@app.before_request
def require_local_access():
    remote = request.remote_addr
    try:
        is_loopback = bool(remote and ipaddress.ip_address(remote).is_loopback)
    except ValueError:
        is_loopback = False
    if not is_loopback:
        return jsonify({"detail": "Remote access is disabled for this local-only build."}), 403

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    return response

@app.errorhandler(RequestEntityTooLarge)
def handle_large_request(_error):
    limit_mib = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
    return jsonify({"detail": f"Request is too large. Maximum request size is {limit_mib:g} MiB."}), 413

@app.errorhandler(HTTPException)
def handle_http_error(error):
    # Keep API errors predictable without exposing server internals.
    if request.path.startswith("/api/"):
        return jsonify({"detail": error.description}), error.code
    return error


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    # Log diagnostic details locally, but never return tracebacks to the browser.
    app.logger.exception("Unhandled application error")
    if request.path.startswith("/api/"):
        return jsonify({"detail": "Internal server error. Please try again."}), 500
    return "Internal server error. Please check the local server log.", 500


# ---------------------------------------------------------
# Page Routes
# ---------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------
# API Routes
# ---------------------------------------------------------
@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "framework": "Flask",
        "version": "0.6.0",
        "environment": os.getenv("FLASK_ENV", "development"),
    })


@app.route("/api/v1/analyze", methods=["POST"])
def analyze_url():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"detail": "Request body must be a JSON object."}), 400
    raw_value = data.get("url", "")
    if not isinstance(raw_value, str):
        return jsonify({"detail": "URL must be a string."}), 400
    raw_url = raw_value.strip()

    if not raw_url:
        return jsonify({"detail": "URL must not be empty."}), 400

    try:
        normalized = normalize_url(raw_url)
    except InvalidURLError as exc:
        return jsonify({"detail": str(exc)}), 400

    # 1. Feature extraction
    features = extract_features(normalized)

    # 2. Independent signal modules
    brand_match = detect_brand_impersonation(features.sld, normalized)
    vt_evidence = get_virustotal_evidence(normalized)
    ml_prediction = predict_phishing_probability(features)
    threat_graph = build_threat_graph(features, brand_match)

    # 3. Multi-signal risk assessment
    assessment = assess_risk(features, brand_match, vt_evidence, ml_prediction, threat_graph)

    graph_dict = threat_graph.to_dict()
    graph_summary = graph_dict.get("summary", {})

    response_data = {
        "normalized_url": normalized,
        "risk_score": assessment.risk_score,
        "confidence": assessment.confidence,
        "classification": assessment.classification,
        "reasons_increasing": assessment.reasons_increasing,
        "reasons_decreasing": assessment.reasons_decreasing,
        "signal_contributions": assessment.signal_contributions,
        "reputation_gap_warning": assessment.reputation_gap_warning,
        "features": features.to_dict(),
        "brand_analysis": brand_match.to_dict(),
        "virustotal": vt_evidence.to_dict(),
        "ml": {
            "available": ml_prediction.available,
            "phishing_probability": ml_prediction.phishing_probability,
            "model_name": ml_prediction.model_name,
            "error": ml_prediction.error,
        },
        "threat_graph": graph_dict,
    }

    # 4. Save to persistent database
    scan_id = None
    try:
        saved_record = save_scan_record(
            url=raw_url,
            normalized_url=normalized,
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            classification=assessment.classification,
            detected_brand=brand_match.detected_brand,
            domain=features.domain,
            domain_age_days=graph_summary.get("domain_age_days"),
            is_recently_registered=graph_summary.get("is_recently_registered", False),
            ssrf_risk=graph_summary.get("ssrf_risk", False),
            full_response_dict=response_data,
        )
        scan_id = saved_record.id
    except Exception as exc:
        print(f"Warning: Failed to save scan record: {exc}")

    response_data["scan_id"] = scan_id
    return jsonify(response_data)


@app.route("/api/v1/analyze/email", methods=["POST"])
def analyze_email_route():
    if 'file' not in request.files:
        return jsonify({"detail": "No file uploaded."}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"detail": "No file selected."}), 400
    if not file.filename.lower().endswith(".eml"):
        return jsonify({"detail": "Email analysis accepts .eml files only."}), 400

    try:
        content = file.stream.read(app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(content) > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify({"detail": f"Uploaded file exceeds the {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):g} MiB limit."}), 413
        if not content:
            return jsonify({"detail": "Uploaded email file is empty."}), 400
        email_data = analyze_email(content)
        # Automatically scan the first extracted URL if any exist
        urls = email_data.get("extracted_urls", [])
        if urls:
            try:
                normalized = normalize_url(urls[0])
            except InvalidURLError:
                email_data["url_analysis"] = {
                    "url": urls[0],
                    "classification": "INCONCLUSIVE",
                    "message": "The extracted URL could not be safely normalized.",
                }
                normalized = None
            if normalized:
                features = extract_features(normalized)
                brand_match = detect_brand_impersonation(features.sld, normalized)
                vt_evidence = get_virustotal_evidence(normalized)
                ml_prediction = predict_phishing_probability(features)
                threat_graph = build_threat_graph(features, brand_match)
                assessment = assess_risk(features, brand_match, vt_evidence, ml_prediction, threat_graph)
            
                email_data["url_analysis"] = {
                    "url": urls[0],
                    "risk_score": assessment.risk_score,
                    "classification": assessment.classification
                }
            
        return jsonify(email_data)
    except Exception as exc:
        app.logger.exception("Email analysis failed")
        return jsonify({"detail": "Failed to analyze email. Check that the file is a valid .eml message."}), 500


@app.route("/api/v1/analyze/email-address", methods=["POST"])
def analyze_email_address_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"detail": "Request body must be a JSON object."}), 400
    raw_email = data.get("email", "")
    if not isinstance(raw_email, str):
        return jsonify({"detail": "Email must be a string."}), 400
    email_val = raw_email.strip()
    if not email_val:
        return jsonify({"detail": "Email address cannot be empty."}), 400
    if len(email_val) > 320:
        return jsonify({"detail": "Email address is too long (max 320 characters)."}), 400

    try:
        result = investigate_email_address(email_val)
        return jsonify(result)
    except Exception:
        app.logger.exception("Email address investigation failed")
        return jsonify({"detail": "Failed to investigate email address."}), 500


@app.route("/api/v1/analyze/file", methods=["POST"])
def analyze_file_route():
    if 'file' not in request.files:
        return jsonify({"detail": "No file uploaded."}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"detail": "No file selected."}), 400

    try:
        content = file.stream.read(app.config["MAX_CONTENT_LENGTH"] + 1)
        if len(content) > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify({"detail": f"Uploaded file exceeds the {app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024):g} MiB limit."}), 413
        if not content:
            return jsonify({"detail": "Uploaded file is empty."}), 400
        file_data = analyze_file(content, file.filename)
        return jsonify(file_data)
    except Exception:
        app.logger.exception("File analysis failed")
        return jsonify({"detail": "Failed to analyze the uploaded file."}), 500


@app.route("/api/v1/graph", methods=["GET"])
def get_graph():
    url_param = request.args.get("url", "").strip()
    if not url_param:
        return jsonify({"detail": "URL parameter is required."}), 400

    try:
        normalized = normalize_url(url_param)
    except InvalidURLError as exc:
        return jsonify({"detail": str(exc)}), 400

    features = extract_features(normalized)
    brand_match = detect_brand_impersonation(features.sld, normalized)
    threat_graph = build_threat_graph(features, brand_match)
    return jsonify(threat_graph.to_dict())


@app.route("/api/v1/adversarial/test", methods=["POST"])
def test_adversarial():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"detail": "Request body must be a JSON object."}), 400
    raw_target = data.get("url", "")
    if not isinstance(raw_target, str):
        return jsonify({"detail": "URL must be a string."}), 400
    target_url = raw_target.strip()

    if not target_url:
        return jsonify({"detail": "Target URL is required for adversarial testing."}), 400

    try:
        report = evaluate_adversarial_resilience(target_url)
        return jsonify(report.to_dict())
    except Exception:
        app.logger.exception("Adversarial testing failed")
        return jsonify({"detail": "Adversarial testing failed. Check the server log for details."}), 500


@app.route("/api/v1/history", methods=["GET"])
def list_history():
    limit = request.args.get("limit", 50, type=int) or 50
    limit = max(1, min(limit, 100))
    scans = get_recent_scans(limit=limit)
    return jsonify(scans)


@app.route("/api/v1/history/<int:scan_id>", methods=["GET"])
def get_history_item(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"detail": "Investigation scan not found."}), 404
    return jsonify(scan)


@app.route("/api/v1/history", methods=["DELETE"])
def delete_history():
    count = clear_all_scans()
    return jsonify({"status": "ok", "deleted_count": count})


@app.route("/api/v1/reports/<int:scan_id>/html", methods=["GET"])
def export_report_html(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"detail": "Investigation scan not found."}), 404

    html_content = generate_investigation_report_html(scan)
    return Response(html_content, mimetype="text/html")


@app.route("/api/v1/reports/<int:scan_id>/json", methods=["GET"])
def export_report_json(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"detail": "Investigation scan not found."}), 404

    return jsonify(generate_investigation_report_json(scan))


@app.route("/api/v1/reports/export/html", methods=["POST"])
def export_live_report_html():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"detail": "Request body must be a JSON object."}), 400
    try:
        html_content = generate_investigation_report_html(payload)
        return Response(html_content, mimetype="text/html; charset=utf-8")
    except Exception:
        app.logger.exception("Live report generation failed")
        return jsonify({"detail": "Failed to generate report."}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(
            "Refusing remote binding: this build has no user authentication. "
            "Keep HOST on 127.0.0.1 until an authenticated deployment is configured."
        )
    print(f"\n=======================================================")
    print(f" PhishTrace AI running at: http://127.0.0.1:{port}")
    print(f" Local-only mode; debug is disabled.")
    print(f"=======================================================\n")
    app.run(host=host, port=port, debug=False)
