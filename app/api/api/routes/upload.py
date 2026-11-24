"""
Email and file upload analysis API routes.

Provides endpoints for uploading .eml email files for header/URL extraction
and generic files for hash computation and metadata analysis.
"""
from fastapi import APIRouter, HTTPException, UploadFile, File

from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import get_virustotal_evidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.graph.builder import build_threat_graph
from app.modules.risk_engine.engine import assess_risk
from app.modules.email_analysis.parser import analyze_email
from app.modules.file_analysis.scanner import analyze_file

router = APIRouter(prefix="/api/v1/analyze", tags=["upload"])


@router.post("/email")
async def analyze_email_upload(file: UploadFile = File(...)) -> dict:
    """
    Accepts an uploaded .eml file, extracts headers and embedded URLs,
    and optionally runs the first extracted URL through the full
    multi-signal analysis pipeline.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected.")

    try:
        content = await file.read()
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

        return email_data

    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to analyze email: {exc}"
        )


@router.post("/file")
async def analyze_file_upload(file: UploadFile = File(...)) -> dict:
    """
    Accepts an uploaded file, computes cryptographic hashes (MD5, SHA-1,
    SHA-256) and returns basic metadata. VT file lookup integration is
    pending — noted inline as a placeholder.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected.")

    try:
        content = await file.read()
        file_data = analyze_file(content, file.filename)
        return file_data

    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to analyze file: {exc}"
        )
