"""
URL lexical/structural feature extraction.

This is real, working feature extraction (not a placeholder) — but it is
intentionally scoped to lexical/structural signals only. Brand similarity,
ML prediction, and VirusTotal evidence are separate modules added in later
phases, per the multi-signal architecture.
"""
import re
from dataclasses import dataclass, asdict

import tldextract

# Use the bundled public-suffix-list snapshot instead of fetching it live
# over the network on every cold start — faster, and works offline/behind
# restrictive network policies.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "password", "banking", "authenticate", "security",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
}


@dataclass
class URLFeatures:
    url: str
    domain: str
    sld: str  # second-level domain label only, e.g. "paypa1-login" (no TLD, no subdomain) — used by brand_detector
    subdomain: str
    suffix: str
    url_length: int
    num_dots: int
    num_hyphens: int
    num_digits: int
    num_subdomains: int
    has_at_symbol: bool
    has_ip_address_host: bool
    is_https: bool
    uses_url_shortener: bool
    suspicious_keyword_count: int
    suspicious_keywords_found: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


IP_HOST_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def extract_features(normalized_url: str) -> URLFeatures:
    extracted = _tld_extractor.extract_str(normalized_url)
    domain = extracted.registered_domain or extracted.domain
    subdomain = extracted.subdomain or ""
    suffix = extracted.suffix or ""

    host = ".".join(part for part in [subdomain, extracted.domain, suffix] if part)
    num_subdomains = len(subdomain.split(".")) if subdomain else 0

    lowered = normalized_url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]

    return URLFeatures(
        url=normalized_url,
        domain=domain,
        sld=extracted.domain or "",
        subdomain=subdomain,
        suffix=suffix,
        url_length=len(normalized_url),
        num_dots=normalized_url.count("."),
        num_hyphens=normalized_url.count("-"),
        num_digits=sum(ch.isdigit() for ch in normalized_url),
        num_subdomains=num_subdomains,
        has_at_symbol="@" in normalized_url,
        has_ip_address_host=bool(IP_HOST_PATTERN.match(host)),
        is_https=normalized_url.startswith("https://"),
        uses_url_shortener=domain in SHORTENER_DOMAINS,
        suspicious_keyword_count=len(found_keywords),
        suspicious_keywords_found=found_keywords,
    )
