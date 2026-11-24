import pytest

from app.core.url_safety import InvalidURLError, normalize_url
from app.modules.file_analysis.scanner import analyze_file
from app.modules.reports.generator import generate_investigation_report_html


@pytest.mark.parametrize(
    "value",
    [
        "https://user:password@example.com/",
        "https://example.com:99999/",
        "https://example.com:invalid/",
        "javascript:alert(1)",
        "https://example.com/with space",
        "https://example.com\\@evil.example/",
        "https://" + ("a" * 8200) + ".example/",
        "https://[not-ipv6]/",
    ],
)
def test_rejects_malformed_or_unsafe_url_input(value):
    with pytest.raises(InvalidURLError):
        normalize_url(value)


def test_normalizes_ipv6_and_preserves_non_default_port():
    assert normalize_url("HTTP://[::1]:8080/path#fragment") == "http://[::1]:8080/path"
    assert normalize_url("Example.COM:8443/login") == "https://example.com:8443/login"


def test_file_hashing_does_not_claim_malware_scanning():
    result = analyze_file(b"harmless test bytes", r"C:\\private\\sample.bin")
    assert result["filename"] == "sample.bin"
    assert result["classification"] == "NOT_SCANNED"
    assert result["risk_score"] is None
    assert "does not establish" in result["message"]
    assert len(result["hashes"]["sha256"]) == 64


def test_report_escapes_untrusted_values():
    payload = {
        "url": "<img src=x onerror=alert(1)>",
        "normalized_url": "https://example.com/<script>alert(1)</script>",
        "risk_score": 10,
        "confidence": 25,
        "classification": "LOW RISK",
        "reasons_increasing": ["<svg onload=alert(1)>"] ,
        "reasons_decreasing": [],
        "features": {"domain": "example.com"},
        "brand_analysis": {"detected_brand": "<img src=x onerror=alert(2)>", "impersonation_risk": "NONE"},
        "virustotal": {},
        "ml": {},
        "threat_graph": {},
    }
    html = generate_investigation_report_html(payload)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;svg onload=alert(1)&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert '<img src=x onerror=alert(1)>' not in html
