"""
Multi-signal risk correlation engine.

WEIGHTING METHOD — justify this choice in the report:
Manual, configurable weights are used rather than learned/calibrated
weighting. This is the academically defensible choice for a BCA project
because: (1) a learned weighting scheme (e.g. stacking a meta-classifier
over the four signals) requires a labeled dataset of *already-scored*
cases large enough to avoid overfitting four inputs, which this project's
realistic dataset size does not support; (2) manual weights keep the
system's decisions traceable end-to-end for the explainability
requirement, whereas a learned combiner reintroduces the "black box"
problem the project is specifically trying to avoid. If a future
iteration has enough evaluation data, recalibrating these weights
empirically (e.g. logistic regression over the four signal scores) would
be the natural next step — noted as future work, not attempted here
without the data to justify it.

Weights below are a STARTING point, deliberately conservative, and must
be revisited once real experiments (Phase 7) show how each signal
actually performs — do not treat them as final without that evidence.
"""
from dataclasses import dataclass, field
from typing import Any

from app.modules.url_features.extractor import URLFeatures
from app.modules.brand_detector.detector import BrandMatch
from app.modules.threat_intelligence.virustotal_client import VirusTotalEvidence
from app.modules.ml.predictor import MLPrediction

# Configurable weights — must sum to 1.0 across signals that are AVAILABLE.
# If a signal is unavailable (e.g. VT down, no model trained yet), its
# weight is redistributed proportionally across the remaining signals
# rather than silently treating the missing signal as "0 risk".
SIGNAL_WEIGHTS = {
    "ml": 0.35,
    "reputation": 0.25,
    "url_structure": 0.20,
    "brand_impersonation": 0.20,
}

BRAND_RISK_TO_SCORE = {"NONE": 0.0, "LOW": 0.35, "MEDIUM": 0.65, "HIGH": 0.9}


@dataclass
class SignalContribution:
    signal: str
    available: bool
    raw_score: float  # 0-1, this signal's own assessment
    weight_used: float  # actual weight applied after redistribution
    detail: str


@dataclass
class RiskAssessment:
    risk_score: int  # 0-100
    confidence: int  # 0-100
    classification: str
    reasons_increasing: list[str] = field(default_factory=list)
    reasons_decreasing: list[str] = field(default_factory=list)
    signal_contributions: list[dict] = field(default_factory=list)
    reputation_gap_warning: bool = False


def _url_structure_score(features: URLFeatures) -> tuple[float, list[str], list[str]]:
    """Real logic ported from the Phase-skeleton placeholder heuristic,
    now normalized to a 0-1 signal score instead of an independent
    0-100 total."""
    points = 0
    max_points = 100
    up, down = [], []

    if not features.is_https:
        points += 15
        up.append("Connection is not HTTPS.")
    else:
        down.append("Uses HTTPS.")

    if features.has_ip_address_host:
        points += 25
        up.append("Host is a raw IP address rather than a domain name.")

    if features.has_at_symbol:
        points += 20
        up.append("URL contains an '@' symbol, which can mask the real destination.")

    if features.uses_url_shortener:
        points += 15
        up.append("URL uses a known link-shortening service, hiding the true destination.")

    if features.num_subdomains >= 3:
        points += 10
        up.append(f"Unusually high number of subdomains ({features.num_subdomains}).")

    if features.suspicious_keyword_count > 0:
        points += min(features.suspicious_keyword_count * 8, 24)
        up.append(
            "Contains authentication-related keywords: "
            + ", ".join(features.suspicious_keywords_found) + "."
        )

    if features.url_length > 100:
        points += 10
        up.append("URL is unusually long.")

    if points == 0:
        down.append("No structural URL anomalies detected.")

    return min(points, max_points) / max_points, up, down


def _redistribute_weights(available_signals: dict[str, bool]) -> dict[str, float]:
    active = {k: w for k, w in SIGNAL_WEIGHTS.items() if available_signals.get(k)}
    total_active_weight = sum(active.values())
    if total_active_weight == 0:
        return {}
    return {k: w / total_active_weight for k, w in active.items()}


def assess_risk(
    features: URLFeatures,
    brand_match: BrandMatch,
    vt_evidence: VirusTotalEvidence,
    ml_prediction: MLPrediction,
    threat_graph: Any | None = None,
) -> RiskAssessment:
    reasons_up: list[str] = []
    reasons_down: list[str] = []

    # Incorporate infrastructure threat signals if threat graph is available
    if threat_graph and hasattr(threat_graph, "summary"):
        summary = threat_graph.summary
        age = summary.get("domain_age_days")
        if age is not None:
            if summary.get("is_critically_young"):
                reasons_up.append(
                    f"Domain is critically young (registered only {age} days ago). "
                    "Brand-new domains are strongly correlated with temporary phishing campaigns."
                )
            elif summary.get("is_recently_registered"):
                reasons_up.append(f"Domain is recently registered ({age} days old).")
            elif age > 730:
                reasons_down.append(f"Domain has an established registration history ({age} days old).")

        if summary.get("ssrf_risk"):
            reasons_up.append("Infrastructure warning: Hostname resolves to private, loopback, or cloud-metadata IP address.")

        if summary.get("is_fast_flux"):
            reasons_up.append("Infrastructure warning: Hostname resolves to multiple IP addresses (potential fast-flux evasion).")

    # --- Score each signal independently on a 0-1 scale ---
    structure_score, s_up, s_down = _url_structure_score(features)
    reasons_up.extend(s_up)
    reasons_down.extend(s_down)

    brand_score = BRAND_RISK_TO_SCORE[brand_match.impersonation_risk]
    if brand_match.impersonation_risk != "NONE":
        reasons_up.append(
            f"Domain resembles the brand '{brand_match.detected_brand}' "
            f"(similarity {brand_match.similarity_score:.0%}, technique: {brand_match.technique})."
        )
        if brand_match.has_extra_auth_keywords:
            reasons_up.append("Brand-like domain is also paired with authentication-related wording.")

    reputation_gap_warning = False
    if vt_evidence.available:
        if vt_evidence.total_engines > 0:
            reputation_score = min(
                (vt_evidence.malicious_count + 0.5 * vt_evidence.suspicious_count)
                / max(vt_evidence.total_engines, 1),
                1.0,
            )
            if vt_evidence.malicious_count > 0:
                reasons_up.append(
                    f"VirusTotal: {vt_evidence.malicious_count}/{vt_evidence.total_engines} "
                    f"engines flagged this URL as malicious."
                )
            else:
                reasons_down.append(
                    f"VirusTotal: 0/{vt_evidence.total_engines} engines flagged this URL."
                )
        else:
            reputation_score = 0.0  # no data ≠ risk signal by itself

        if vt_evidence.reputation_gap:
            reputation_gap_warning = True
    else:
        reputation_score = None  # unavailable, handled below

    ml_score = ml_prediction.phishing_probability if ml_prediction.available else None
    if ml_prediction.available:
        if ml_score >= 0.5:
            reasons_up.append(f"ML model estimates a {ml_score:.0%} probability of phishing.")
        else:
            reasons_down.append(f"ML model estimates a low ({ml_score:.0%}) probability of phishing.")

    # --- Combine with weight redistribution for unavailable signals ---
    availability = {
        "ml": ml_prediction.available,
        "reputation": vt_evidence.available,
        "url_structure": True,  # always available, computed locally
        "brand_impersonation": True,  # always available, computed locally
    }
    active_weights = _redistribute_weights(availability)

    signal_scores = {
        "ml": ml_score or 0.0,
        "reputation": reputation_score or 0.0,
        "url_structure": structure_score,
        "brand_impersonation": brand_score,
    }

    combined = sum(signal_scores[k] * w for k, w in active_weights.items())
    risk_score = round(combined * 100)

    # --- Low-reputation early warning override ---
    # If VT shows little/no detection but other independent signals are
    # strongly positive, don't let a clean VT result silently cancel them out
    # — this is the project's core "reputation gap" thesis, not decoration.
    if reputation_gap_warning and (brand_score >= 0.65 or (ml_score or 0) >= 0.7):
        reasons_up.append(
            "Low-reputation early warning: VirusTotal shows little or no detection, "
            "but independent signals (brand similarity and/or ML prediction) indicate "
            "meaningful risk. Low reputation does not necessarily mean low risk."
        )
        risk_score = max(risk_score, 60)  # floor, not override — evidence-based, not arbitrary

    risk_score = min(max(risk_score, 0), 100)

    # --- Confidence: based on how much evidence is actually available ---
    available_count = sum(availability.values())
    confidence = round((available_count / len(availability)) * 100)
    if vt_evidence.available and vt_evidence.total_engines == 0:
        confidence -= 10  # VT reachable but has literally no prior data on this URL
    confidence = min(max(confidence, 10), 100)

    if risk_score >= 70:
        classification = "HIGH RISK"
    elif risk_score >= 45:
        classification = "SUSPICIOUS"
    elif risk_score >= 20:
        classification = "LOW RISK"
    else:
        classification = "LOW RISK"

    if not reasons_up:
        reasons_up.append("No significant risk indicators found across available signals.")

    contributions = [
        SignalContribution(
            signal=k,
            available=availability[k],
            raw_score=round(signal_scores[k], 3),
            weight_used=round(active_weights.get(k, 0.0), 3),
            detail=_signal_detail(k, availability, vt_evidence, ml_prediction),
        ).__dict__
        for k in SIGNAL_WEIGHTS
    ]

    return RiskAssessment(
        risk_score=risk_score,
        confidence=confidence,
        classification=classification,
        reasons_increasing=reasons_up,
        reasons_decreasing=reasons_down,
        signal_contributions=contributions,
        reputation_gap_warning=reputation_gap_warning,
    )


def _signal_detail(signal: str, availability: dict, vt: VirusTotalEvidence, ml: MLPrediction) -> str:
    if signal == "ml" and not availability["ml"]:
        return ml.error or "ML signal unavailable."
    if signal == "reputation" and not availability["reputation"]:
        return vt.error or "VirusTotal evidence unavailable; assessment continues using available signals."
    return "Computed locally."
