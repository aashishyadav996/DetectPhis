from app.modules.brand_detector.detector import detect_brand_impersonation


def test_detect_legitimate_brand():
    # Exactly PayPal's own brand should be classified as NONE
    match = detect_brand_impersonation("paypal", "https://paypal.com/login")
    assert match.impersonation_risk == "NONE"
    assert match.detected_brand is None


def test_detect_homoglyph_impersonation():
    # paypa1 with '1' instead of 'l'
    match = detect_brand_impersonation("paypa1", "https://paypa1.com/verify")
    assert match.impersonation_risk in ("HIGH", "MEDIUM")
    assert match.detected_brand == "PayPal"


def test_detect_brand_insertion():
    # Brand inserted in longer domain
    match = detect_brand_impersonation("paypal-security-update", "https://paypal-security-update.com/login")
    assert match.impersonation_risk == "HIGH"
    assert match.detected_brand == "PayPal"
    assert match.has_extra_auth_keywords is True


def test_detect_unrelated_domain():
    match = detect_brand_impersonation("acmewidgets123", "https://acmewidgets123.com/")
    assert match.impersonation_risk == "NONE"
