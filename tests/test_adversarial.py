from app.modules.adversarial.generator import generate_mutations
from app.modules.adversarial.evaluator import evaluate_adversarial_resilience
from app.modules.adversarial.models import MutationTechnique


def test_generate_mutations():
    url = "https://paypal.com/signin"
    mutations = generate_mutations(url)

    assert len(mutations) >= 6

    techniques = [m["technique"] for m in mutations]
    assert MutationTechnique.HOMOGLYPH_SUBSTITUTION.value in techniques
    assert MutationTechnique.SUBDOMAIN_NESTING.value in techniques
    assert MutationTechnique.AT_SIGN_DESTINATION_MASK.value in techniques
    assert MutationTechnique.AUTH_KEYWORD_PADDING.value in techniques

    for m in mutations:
        assert m["mutated_url"].startswith("http")
        assert len(m["description"]) > 0


def test_evaluate_adversarial_resilience():
    url = "https://paypal.com/signin"
    report = evaluate_adversarial_resilience(url)

    assert report.total_mutations > 0
    assert report.detected_count + report.evaded_count == report.total_mutations
    assert 0.0 <= report.resilience_rate_percent <= 100.0
    assert len(report.mutations) == report.total_mutations
    assert len(report.vulnerability_summary) > 0

    report_dict = report.to_dict()
    assert "resilience_rate_percent" in report_dict
    assert "mutations" in report_dict
