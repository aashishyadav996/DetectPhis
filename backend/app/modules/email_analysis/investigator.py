"""
Email Address Investigation Module.

Investigates an email address (user@domain.com) by:
  1. Validating the email format
  2. Extracting the local part and domain
  3. DNS MX record lookup (mail server check)
  4. DNS A record lookup on the domain
  5. RDAP/WHOIS domain age and registrar profiling
  6. Brand impersonation check on the domain
  7. Disposable/free email provider detection
  8. Suspicious pattern analysis on the local part
  9. Overall risk score with reasons
"""

import re
import socket
import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Known disposable / free / bulk email provider domains
# ---------------------------------------------------------------------------
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "sharklasers.com", "guerrillamailblock.com", "grr.la", "guerrillamail.info",
    "guerrillamail.biz", "guerrillamail.de", "guerrillamail.net", "guerrillamail.org",
    "spam4.me", "yopmail.com", "yopmail.fr", "cool.fr.nf", "jetable.fr.nf",
    "nospam.ze.tc", "nomail.xl.cx", "mega.zik.dj", "speed.1s.fr",
    "courriel.fr.nf", "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf",
    "trashmail.com", "trashmail.me", "trashmail.at", "trashmail.io",
    "trashmail.net", "dispostable.com", "maildrop.cc", "getnada.com",
    "10minutemail.com", "10minutemail.net", "mytemp.email", "fakeinbox.com",
    "discard.email", "throwam.com", "spamgourmet.com", "spamgourmet.net",
    "mailnull.com", "spamfree24.org", "spamfree24.de", "spamfree.eu",
    "spam.la", "antispam24.de", "sogetthis.com",
}

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr", "outlook.com", "outlook.fr",
    "live.com", "live.co.uk", "aol.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "tutanota.com", "tutamail.com",
    "zoho.com", "gmx.com", "gmx.de", "gmx.net", "web.de", "t-online.de",
}

# Regex for RFC-5321 basic email validation
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

# Suspicious patterns in the local part
SUSPICIOUS_LOCAL_PATTERNS = [
    (re.compile(r"\d{6,}"),            "Local part contains long numeric sequence"),
    (re.compile(r"[._\-]{2,}"),        "Local part has consecutive special characters"),
    (re.compile(r"^(admin|info|support|noreply|no-reply|billing|security|"
                r"verify|account|update|helpdesk|alert|service|team|staff|"
                r"paypal|apple|amazon|google|microsoft|bank)\b", re.I),
     "Local part uses impersonation keyword"),
    (re.compile(r"^[a-z]{1,3}\d{4,}$", re.I), "Local part looks auto-generated (short letters + long digits)"),
]


def _mx_lookup(domain: str) -> list[str]:
    """Returns MX hostnames for the domain, or empty list on failure."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "MX", lifetime=4)
        return sorted(
            [str(r.exchange).rstrip(".") for r in answers],
            key=lambda x: x
        )
    except Exception:
        pass
    # Fallback: raw socket won't do MX — return empty to indicate no MX found
    return []


def _a_lookup(domain: str) -> list[str]:
    """Returns A record IPs for the domain."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _rdap_domain_age(domain: str) -> Optional[int]:
    """
    Returns estimated domain age in days via ICANN RDAP, or None on failure.
    """
    try:
        import httpx
        resp = httpx.get(
            f"https://rdap.org/domain/{domain}",
            timeout=5,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for event in data.get("events", []):
            if event.get("eventAction") in ("registration", "Registration"):
                reg_date_str = event.get("eventDate", "")
                if reg_date_str:
                    reg_date = datetime.datetime.fromisoformat(
                        reg_date_str.replace("Z", "+00:00")
                    )
                    age = (datetime.datetime.now(datetime.timezone.utc) - reg_date).days
                    return age
    except Exception:
        pass
    return None


def _registrar_info(domain: str) -> Optional[str]:
    """Returns registrar name via RDAP, or None."""
    try:
        import httpx
        resp = httpx.get(
            f"https://rdap.org/domain/{domain}",
            timeout=5,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if vcard and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            return item[3]
    except Exception:
        pass
    return None


def investigate_email_address(email: str) -> dict:
    """
    Full email address investigation. Returns a structured result dict.
    """
    email = email.strip().lower()

    # 1. Format validation
    if not EMAIL_REGEX.match(email):
        return {
            "email": email,
            "valid_format": False,
            "error": "Invalid email address format.",
            "risk_score": 80,
            "risk_level": "HIGH",
            "reasons": ["Email address does not match a valid format (user@domain.tld)."],
        }

    local_part, domain = email.rsplit("@", 1)

    reasons_increasing = []
    reasons_decreasing = []
    risk_score = 0

    # 2. Disposable provider check
    is_disposable = domain in DISPOSABLE_DOMAINS
    if is_disposable:
        risk_score += 45
        reasons_increasing.append(f"Domain '{domain}' is a known disposable/temporary email provider.")

    # 3. Free provider check
    is_free_provider = domain in FREE_PROVIDERS
    if is_free_provider and not is_disposable:
        risk_score += 10
        reasons_increasing.append(f"Domain '{domain}' is a free consumer email provider (not business).")
    elif not is_free_provider and not is_disposable:
        reasons_decreasing.append("Domain appears to be a custom/business domain.")

    # 4. Suspicious local-part patterns
    local_flags = []
    for pattern, description in SUSPICIOUS_LOCAL_PATTERNS:
        if pattern.search(local_part):
            local_flags.append(description)
            risk_score += 15
            reasons_increasing.append(description)

    # 5. DNS MX lookup
    mx_records = _mx_lookup(domain)
    has_mx = len(mx_records) > 0
    if not has_mx:
        risk_score += 30
        reasons_increasing.append(f"Domain '{domain}' has no MX records — cannot receive email.")
    else:
        reasons_decreasing.append(f"Domain has valid MX record(s): {', '.join(mx_records[:2])}")

    # 6. DNS A lookup
    a_records = _a_lookup(domain)
    has_a = len(a_records) > 0
    if not has_a:
        risk_score += 20
        reasons_increasing.append(f"Domain '{domain}' has no A record — domain may not exist.")

    # 7. Domain age via RDAP
    domain_age_days = _rdap_domain_age(domain)
    registrar = _registrar_info(domain)
    is_recently_registered = False
    if domain_age_days is not None:
        if domain_age_days < 30:
            is_recently_registered = True
            risk_score += 35
            reasons_increasing.append(
                f"Domain was registered only {domain_age_days} day(s) ago — very recently registered."
            )
        elif domain_age_days < 180:
            is_recently_registered = True
            risk_score += 15
            reasons_increasing.append(
                f"Domain is relatively new ({domain_age_days} days old)."
            )
        else:
            reasons_decreasing.append(
                f"Domain has been registered for {domain_age_days} days — established domain."
            )
    else:
        reasons_increasing.append("Could not verify domain age via RDAP (domain may be unregistered or private).")
        risk_score += 10

    # 8. Brand impersonation check on domain
    try:
        from app.modules.brand_detector.detector import detect_brand_impersonation
        brand_match = detect_brand_impersonation(domain.split(".")[0], f"http://{domain}")
        brand_result = brand_match.to_dict()
        if brand_result.get("detected_brand"):
            risk_score += 25
            reasons_increasing.append(
                f"Domain appears to impersonate '{brand_result['detected_brand']}' "
                f"(similarity: {round(brand_result.get('similarity_score', 0) * 100)}%)."
            )
    except Exception:
        brand_result = {"detected_brand": None}

    # 9. Clamp score
    risk_score = min(100, max(0, risk_score))

    # Determine risk level
    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "SUSPICIOUS"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "email": email,
        "local_part": local_part,
        "domain": domain,
        "valid_format": True,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons_increasing": reasons_increasing,
        "reasons_decreasing": reasons_decreasing,
        "dns": {
            "mx_records": mx_records,
            "has_mx": has_mx,
            "a_records": a_records,
            "has_a": has_a,
        },
        "domain_info": {
            "domain_age_days": domain_age_days,
            "is_recently_registered": is_recently_registered,
            "registrar": registrar,
            "is_disposable": is_disposable,
            "is_free_provider": is_free_provider,
        },
        "brand_analysis": brand_result,
        "local_part_flags": local_flags,
    }
