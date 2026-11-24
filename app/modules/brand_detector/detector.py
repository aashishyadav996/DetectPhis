"""
Brand impersonation detector.

Compares a URL's domain against a known-brands list using multiple
similarity techniques, since string-matching alone misses common
impersonation tricks (character substitution, homoglyphs, brand-name
insertion into a longer domain).

LIMITATION (state honestly in the report): this only detects
impersonation of brands present in KNOWN_BRANDS below. It is a
demonstration set for a BCA project scope, not an exhaustive brand
database — real products (e.g. commercial anti-phishing tools) use
databases with thousands of tracked brands. Expanding this list is a
legitimate, low-risk way to strengthen the project if time allows.
"""
from dataclasses import dataclass, asdict

import jellyfish

# Canonical domain (without TLD) -> display name.
# Deliberately a small, clearly-scoped demonstration set.
KNOWN_BRANDS: dict[str, str] = {
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "amazon": "Amazon",
    "facebook": "Facebook",
    "google": "Google",
    "apple": "Apple",
    "netflix": "Netflix",
    "instagram": "Instagram",
    "linkedin": "LinkedIn",
    "bankofamerica": "Bank of America",
    "chase": "Chase",
    "wellsfargo": "Wells Fargo",
    "dhl": "DHL",
    "outlook": "Outlook",
}

# Common homoglyph / leetspeak substitutions seen in phishing domains.
# Maps look-alike character -> the character it's meant to imitate.
HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "rn": "m",
    "vv": "w",
    "cl": "d",
}

AUTH_KEYWORDS = ["login", "signin", "secure", "verify", "account", "security", "update", "auth"]


@dataclass
class BrandMatch:
    detected_brand: str | None
    canonical_domain: str | None
    similarity_score: float  # 0-1
    technique: str | None
    impersonation_risk: str  # NONE / LOW / MEDIUM / HIGH
    has_extra_auth_keywords: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _normalize_homoglyphs(text: str) -> str:
    normalized = text
    # Multi-character substitutions first, so "rn" doesn't get partially
    # consumed by single-character rules before the pair is checked.
    for fake, real in sorted(HOMOGLYPH_MAP.items(), key=lambda kv: -len(kv[0])):
        normalized = normalized.replace(fake, real)
    return normalized


def _classify_risk(score: float) -> str:
    if score >= 0.92:
        return "HIGH"
    if score >= 0.80:
        return "MEDIUM"
    if score >= 0.65:
        return "LOW"
    return "NONE"


def detect_brand_impersonation(domain: str, full_url: str) -> BrandMatch:
    """
    domain: registered domain without suffix, e.g. "paypa1-login-security"
            (caller passes the SLD portion; see extractor.URLFeatures.domain
            which currently includes the suffix — see risk_engine integration
            for how this is derived).
    """
    domain_lower = domain.lower()
    normalized_domain = _normalize_homoglyphs(domain_lower)

    # If the domain is EXACTLY a known brand's own name, this is legitimate
    # use of that brand's domain, not impersonation of it — short-circuit
    # before any similarity scoring runs, so it can't be out-matched by a
    # weak, spurious similarity to a *different* brand.
    if domain_lower in KNOWN_BRANDS:
        return BrandMatch(
            detected_brand=None,
            canonical_domain=None,
            similarity_score=0.0,
            technique=None,
            impersonation_risk="NONE",
            has_extra_auth_keywords=any(kw in full_url.lower() for kw in AUTH_KEYWORDS),
        )

    best_brand = None
    best_canonical = None
    best_score = 0.0
    best_technique = None

    for brand_key, display_name in KNOWN_BRANDS.items():
        # Exact substring match on the raw domain or normalized domain = clear brand-name insertion
        if (brand_key in domain_lower and domain_lower != brand_key) or (brand_key in normalized_domain and normalized_domain != brand_key):
            score = 0.97 if brand_key in domain_lower else 0.95
            technique = (
                "Brand name inserted into a longer/modified domain"
                if brand_key in domain_lower
                else "Homoglyph brand insertion into modified domain"
            )
            if score > best_score:
                best_brand, best_canonical, best_score, best_technique = (
                    display_name, brand_key, score, technique,
                )
            continue

        jw_raw = jellyfish.jaro_winkler_similarity(domain_lower, brand_key)
        jw_normalized = jellyfish.jaro_winkler_similarity(normalized_domain, brand_key)

        if jw_normalized > jw_raw and jw_normalized >= 0.90:
            score = jw_normalized
            technique = "Homoglyph / character substitution"
        else:
            score = jw_raw
            technique = "String similarity to known brand"

        if score > best_score:
            best_brand, best_canonical, best_score, best_technique = (
                display_name, brand_key, score, technique,
            )

    has_auth_keywords = any(kw in full_url.lower() for kw in AUTH_KEYWORDS)

    risk = _classify_risk(best_score) if best_brand else "NONE"

    return BrandMatch(
        detected_brand=best_brand if risk != "NONE" else None,
        canonical_domain=best_canonical if risk != "NONE" else None,
        similarity_score=round(best_score, 3) if best_brand else 0.0,
        technique=best_technique if risk != "NONE" else None,
        impersonation_risk=risk,
        has_extra_auth_keywords=has_auth_keywords,
    )
