import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import repository
from app.database.models import Base
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


@pytest.fixture
def isolated_scan_database(monkeypatch, tmp_path):
    """Never let tests clear or modify the user's real scan history."""
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test_scans.db'}")
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    monkeypatch.setattr(repository, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(repository, "init_db", lambda: Base.metadata.create_all(bind=test_engine))
    yield
    test_engine.dispose()


def test_database_crud_and_reports(isolated_scan_database):
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
