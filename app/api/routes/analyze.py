from fastapi import APIRouter, HTTPException

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import get_virustotal_evidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.graph.builder import build_threat_graph
from app.modules.risk_engine.engine import assess_risk
from app.database.repository import save_scan_record
from app.models.schemas import AnalyzeRequest, AnalyzeResponse

router = APIRouter(prefix="/api/v1", tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_url(payload: AnalyzeRequest) -> AnalyzeResponse:
    try:
        normalized = normalize_url(payload.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    features = extract_features(normalized)

    # Each signal module is independently fault-tolerant (see their own
    # docstrings) — a failure in one must never take down the others.
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

    # Persist scan to database
    scan_id = None
    try:
        saved_record = save_scan_record(
            url=payload.url,
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
        pass  # Persistence failure must never block real-time analysis result

    response_data["scan_id"] = scan_id
    return AnalyzeResponse(**response_data)


@router.get("/graph")
def get_graph_for_url(url: str) -> dict:
    try:
        normalized = normalize_url(url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    features = extract_features(normalized)
    brand_match = detect_brand_impersonation(features.sld, normalized)
    threat_graph = build_threat_graph(features, brand_match)
    return threat_graph.to_dict()
