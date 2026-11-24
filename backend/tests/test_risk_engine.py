from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import VirusTotalEvidence
from app.modules.ml.predictor import MLPrediction
from app.modules.risk_engine.engine import assess_risk
from app.modules.graph.builder import build_threat_graph


def test_assess_risk_high_threat():
    url = "https://paypa1-security-login.com/verify?account=1"
    features = extract_features(url)
    brand_match = detect_brand_impersonation(features.sld, url)
    vt_evidence = VirusTotalEvidence(available=False, error="No key")
    ml_prediction = MLPrediction(available=True, phishing_probability=0.88, model_name="RandomForestClassifier")
    threat_graph = build_threat_graph(features, brand_match, skip_network_calls=True)

    assessment = assess_risk(features, brand_match, vt_evidence, ml_prediction, threat_graph)

    assert assessment.risk_score >= 60
    assert assessment.classification in ("HIGH RISK", "SUSPICIOUS")
    assert len(assessment.reasons_increasing) > 0
    assert assessment.confidence > 0


def test_assess_risk_weight_redistribution_when_signals_missing():
    url = "https://example.com/"
    features = extract_features(url)
    brand_match = detect_brand_impersonation(features.sld, url)
    vt_evidence = VirusTotalEvidence(available=False, error="Offline")
    ml_prediction = MLPrediction(available=False, error="Model missing")

    assessment = assess_risk(features, brand_match, vt_evidence, ml_prediction)

    # Active weights should sum to 1.0 across available signals
    active_weights_sum = sum(c["weight_used"] for c in assessment.signal_contributions if c["available"])
    assert round(active_weights_sum, 2) == 1.00
