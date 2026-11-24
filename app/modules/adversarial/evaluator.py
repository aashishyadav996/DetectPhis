"""
Adversarial Resilience Evaluator.
Executes generated mutations against the multi-signal risk engine,
measures detection rates versus evasion success, and generates vulnerability insights.
"""
from app.core.url_safety import normalize_url, InvalidURLError
from app.modules.url_features.extractor import extract_features
from app.modules.brand_detector.detector import detect_brand_impersonation
from app.modules.threat_intelligence.virustotal_client import VirusTotalEvidence
from app.modules.ml.predictor import predict_phishing_probability
from app.modules.risk_engine.engine import assess_risk
from app.modules.graph.builder import build_threat_graph
from app.modules.adversarial.models import (
    MutatedCandidate,
    AdversarialTestReport,
)
from app.modules.adversarial.generator import generate_mutations


def evaluate_adversarial_resilience(url: str) -> AdversarialTestReport:
    """
    Evaluates engine robustness against a generated suite of adversarial mutations for the given URL.
    """
    try:
        normalized_base = normalize_url(url)
    except InvalidURLError:
        normalized_base = url if url.startswith("http") else f"https://{url}"

    # 1. Baseline analysis of original URL
    base_features = extract_features(normalized_base)
    base_brand = detect_brand_impersonation(base_features.sld, normalized_base)
    base_ml = predict_phishing_probability(base_features)
    base_vt = VirusTotalEvidence(available=False, error="Adversarial evaluation uses offline signal suite")
    base_graph = build_threat_graph(base_features, base_brand, skip_network_calls=True)
    baseline_assessment = assess_risk(base_features, base_brand, base_vt, base_ml, base_graph)
    baseline_score = baseline_assessment.risk_score

    # 2. Generate adversarial mutations
    mutation_specs = generate_mutations(normalized_base)
    evaluated_mutations: list[MutatedCandidate] = []

    detected_count = 0
    evaded_count = 0

    for spec in mutation_specs:
        mutated_url = spec["mutated_url"]
        try:
            norm_mut = normalize_url(mutated_url)
        except InvalidURLError:
            norm_mut = mutated_url

        mut_features = extract_features(norm_mut)
        mut_brand = detect_brand_impersonation(mut_features.sld, norm_mut)
        mut_ml = predict_phishing_probability(mut_features)
        mut_graph = build_threat_graph(mut_features, mut_brand, skip_network_calls=True)

        mut_assessment = assess_risk(mut_features, mut_brand, base_vt, mut_ml, mut_graph)
        score = mut_assessment.risk_score
        classification = mut_assessment.classification

        # A phishing mutation is considered successfully detected if risk is Suspicious or High (>= 45)
        detected = score >= 45
        evasion_success = not detected

        if detected:
            detected_count += 1
        else:
            evaded_count += 1

        factors = mut_assessment.reasons_increasing[:2] if mut_assessment.reasons_increasing else ["No strong risk signals triggered"]

        evaluated_mutations.append(
            MutatedCandidate(
                technique=spec["technique"],
                mutated_url=norm_mut,
                description=spec["description"],
                risk_score=score,
                classification=classification,
                detected=detected,
                evasion_success=evasion_success,
                key_factors=factors,
            )
        )

    total = len(evaluated_mutations)
    resilience_rate = (detected_count / total * 100) if total > 0 else 100.0

    # 3. Generate actionable vulnerability summary
    vulnerabilities: list[str] = []
    evaded_techniques = [m.technique for m in evaluated_mutations if m.evasion_success]

    if not evaded_techniques:
        vulnerabilities.append(
            "Optimal Resilience: All generated adversarial mutations (homoglyphs, typosquatting, subdomain masking) "
            "were successfully flagged as Suspicious or High Risk by the multi-signal engine."
        )
    else:
        vulnerabilities.append(
            f"Evasion Blind Spots: {len(evaded_techniques)} mutation(s) slipped below the detection threshold: "
            + ", ".join(set(evaded_techniques)) + "."
        )
        if any("Typosquatting" in t for t in evaded_techniques):
            vulnerabilities.append(
                "Recommendation: Broaden Jaro-Winkler similarity thresholds for single-character omission/transposition."
            )
        if any("Subdomain" in t for t in evaded_techniques):
            vulnerabilities.append(
                "Recommendation: Increase lexical feature weight for deep subdomain nesting when apex domain is unfamiliar."
            )

    return AdversarialTestReport(
        original_url=normalized_base,
        baseline_risk_score=baseline_score,
        total_mutations=total,
        detected_count=detected_count,
        evaded_count=evaded_count,
        resilience_rate_percent=resilience_rate,
        mutations=evaluated_mutations,
        vulnerability_summary=vulnerabilities,
    )
