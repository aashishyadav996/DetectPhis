import pytest
from app.core.url_safety import normalize_url, InvalidURLError


def test_normalize_valid_url():
    assert normalize_url("paypal.com") == "https://paypal.com/"
    assert normalize_url("http://example.com/login") == "http://example.com/login"
    assert normalize_url("https://sub.domain.com/path?query=1#frag") == "https://sub.domain.com/path?query=1"


def test_normalize_empty_url():
    with pytest.raises(InvalidURLError):
        normalize_url("")
    with pytest.raises(InvalidURLError):
        normalize_url("   ")


def test_normalize_invalid_scheme():
    with pytest.raises(InvalidURLError):
        normalize_url("ftp://example.com")
    with pytest.raises(InvalidURLError):
        normalize_url("javascript:alert(1)")
