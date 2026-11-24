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


def test_database_crud_and_reports():
    clear_all_scans()

    record = save_scan_record(
        url="https://paypa1-security.com/verify",
        normalized_url="https://paypa1-security.com/verify",
        risk_score=85,
        confidence=80,
        classification="HIGH RISK",
        detected_brand="PayPal",
        domain="paypa1-security.com",
        domain_age_days=6,
        is_recently_registered=True,
        ssrf_risk=False,
        full_response_dict={
            "reasons_increasing": ["Critically young domain", "Brand impersonation detected"],
            "reasons_decreasing": [],
            "features": {"is_https": True},
            "brand_analysis": {"detected_brand": "PayPal", "impersonation_risk": "HIGH"},
            "threat_graph": {"threat_indicators": ["Young domain"]},
        },
    )

    assert record.id is not None
    assert record.risk_score == 85

    # Test retrieval
    fetched = get_scan_by_id(record.id)
    assert fetched is not None
    assert fetched["normalized_url"] == "https://paypa1-security.com/verify"

    recent = get_recent_scans(limit=10)
    assert len(recent) >= 1
    assert recent[0]["id"] == record.id

    # Test report generation
    json_report = generate_investigation_report_json(fetched)
    assert "report_id" in json_report
    assert "integrity_sha256" in json_report
    assert json_report["investigation"]["risk_score"] == 85

    html_report = generate_investigation_report_html(fetched)
    assert "<!DOCTYPE html>" in html_report
    assert "PhishTrace AI" in html_report
    assert "paypa1-security.com/verify" in html_report
    assert "HIGH RISK" in html_report

    # Cleanup
    cleared_count = clear_all_scans()
    assert cleared_count >= 1
