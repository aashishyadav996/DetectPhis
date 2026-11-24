"""
Unit tests for Email Analysis and Email ID Investigator modules.
"""
import pytest
import importlib.util
import pathlib
from app.modules.email_analysis.investigator import investigate_email_address
from app.modules.email_analysis.parser import analyze_email

# Load app from root app.py
app_path = pathlib.Path(__file__).parent.parent / "app.py"
spec = importlib.util.spec_from_file_location("root_app", str(app_path))
root_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(root_app)
flask_app = root_app.app


def test_investigate_valid_free_email():
    result = investigate_email_address("test.user@gmail.com")
    assert result["valid_format"] is True
    assert result["email"] == "test.user@gmail.com"
    assert result["local_part"] == "test.user"
    assert result["domain"] == "gmail.com"
    assert result["domain_info"]["is_free_provider"] is True
    assert result["domain_info"]["is_disposable"] is False
    assert result["dns"]["has_mx"] is True
    assert result["risk_score"] < 50


def test_investigate_disposable_email():
    result = investigate_email_address("victim123@mailinator.com")
    assert result["valid_format"] is True
    assert result["domain"] == "mailinator.com"
    assert result["domain_info"]["is_disposable"] is True
    assert result["risk_score"] >= 40
    assert any("disposable" in r.lower() for r in result["reasons_increasing"])


def test_investigate_brand_spoofing_email():
    result = investigate_email_address("security@paypa1-login.com")
    assert result["valid_format"] is True
    assert result["risk_score"] >= 60
    assert result["risk_level"] in ("HIGH", "SUSPICIOUS")
    assert result["brand_analysis"]["detected_brand"] == "PayPal"
    assert any("impersonat" in r.lower() for r in result["reasons_increasing"])


def test_investigate_malformed_email():
    result = investigate_email_address("invalid-email-no-at")
    assert result["valid_format"] is False
    assert result["risk_score"] >= 70
    assert "reasons_increasing" in result


def test_analyze_email_file_headers_and_id():
    eml_sample = b"""From: "PayPal Support" <support@paypa1-update.com>
To: target@example.com
Subject: URGENT: Verify your account immediately
Date: Mon, 12 Oct 2026 10:00:00 +0000
Message-ID: <123456789@paypa1-update.com>
Content-Type: text/plain; charset=utf-8

Please click here to verify: https://paypa1-update.com/signin
"""
    result = analyze_email(eml_sample)
    headers = result["headers"]

    assert headers["from_email_id"] == "support@paypa1-update.com"
    assert headers["to_email_id"] == "target@example.com"
    assert headers["message_id"] == "<123456789@paypa1-update.com>"
    assert result["sender_email_id_investigation"] is not None
    assert result["sender_email_id_investigation"]["domain"] == "paypa1-update.com"
    assert result["risk_score"] >= 35
    assert len(result["extracted_urls"]) == 1


def test_api_email_address_endpoint():
    client = flask_app.test_client()
    resp = client.post("/api/v1/analyze/email-address", json={"email": "security@paypa1-verify.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["email"] == "security@paypa1-verify.com"
    assert data["valid_format"] is True
    assert "risk_score" in data


def test_api_email_address_empty_rejected():
    client = flask_app.test_client()
    resp = client.post("/api/v1/analyze/email-address", json={"email": "  "})
    assert resp.status_code == 400
