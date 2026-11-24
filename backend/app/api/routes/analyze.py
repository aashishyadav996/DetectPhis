"""
URL analysis Flask Blueprint.
"""
from flask import Blueprint, request, jsonify, abort

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import get_virustotal_evidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.graph.builder import build_threat_graph
from app.modules.risk_engine.engine import assess_risk
from app.database.repository import save_scan_record

analyze_bp = Blueprint("analyze", __name__, url_prefix="/api/v1")


@analyze_bp.route("/analyze", methods=["POST"])
def analyze_url():
    body = request.get_json(silent=True)
    if not body or not body.get("url"):
        abort(400, description="Missing required field: url")

    url_input = body["url"].strip()
    if not url_input or len(url_input) > 2048:
        abort(400, description="URL must be between 1 and 2048 characters.")

    try:
        normalized = normalize_url(url_input)
    except InvalidURLError as exc:
        abort(400, description=str(exc))

    features = extract_features(normalized)

    # Each signal module is independently fault-tolerant — a failure in one
    # must never take down the others.
    brand_match = detect_brand_impersonation(features.sld, normalized)
    vt_evidence = get_virustotal_evidence(normalized)
    ml_prediction = predict_phishing_probability(features)
    threat_graph = build_threat_graph(features, brand_match)

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

    # Persist scan to database — failure must never block analysis result
    scan_id = None
    try:
        # Pre-assign scan_id placeholder so the stored details_json blob contains a
        # consistent reference — it will be updated once we have the real DB id.
        response_data["scan_id"] = None
        saved_record = save_scan_record(
            url=url_input,
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
    except Exception:
        pass

    response_data["scan_id"] = scan_id
    return jsonify(response_data), 200


@analyze_bp.route("/graph", methods=["GET"])
def get_graph_for_url():
    url = request.args.get("url", "").strip()
    if not url:
        abort(400, description="Missing query parameter: url")

    try:
        normalized = normalize_url(url)
    except InvalidURLError as exc:
        abort(400, description=str(exc))

    features = extract_features(normalized)
    brand_match = detect_brand_impersonation(features.sld, normalized)
    threat_graph = build_threat_graph(features, brand_match)
    return jsonify(threat_graph.to_dict()), 200
