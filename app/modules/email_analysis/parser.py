"""
Email Analysis Module — Full phishing detection for .eml files.

Checks:
  - SPF / DKIM / DMARC authentication headers
  - Sender domain vs display-name spoofing
  - Reply-To mismatch
  - Urgency/threat language in subject and body
  - Suspicious link count and domains
  - Attachment extensions (executables, scripts, macros)
  - Overall phishing risk score with plain-English verdict
"""
import email
import re
from email.policy import default
from urllib.parse import urlparse

# ── Patterns ────────────────────────────────────────────────────────────────

URL_REGEX = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:[/\w.\-?=&#%@!+]*)?',
    re.IGNORECASE,
)

URGENCY_WORDS = [
    "urgent", "immediately", "action required", "verify now", "account suspended",
    "limited time", "expire", "expiring", "click here", "confirm your",
    "update your", "unusual activity", "unauthorized", "suspicious login",
    "your account has been", "password", "security alert", "won", "winner",
    "prize", "lottery", "congratulations", "free", "gift card", "invoice",
    "payment", "transaction", "bank", "kyc", "otp", "one-time",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".ps2", ".psc1", ".psc2", ".msi", ".msp", ".com", ".scr",
    ".hta", ".lnk", ".reg", ".inf", ".jar", ".py", ".sh",
    ".doc", ".docm", ".xlsm", ".xls", ".pptm",  # macro-enabled Office
    ".zip", ".rar", ".7z", ".iso", ".img",         # archives (common malware delivery)
}

SAFE_FREE_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "protonmail.com", "icloud.com", "aol.com",
}

SUSPICIOUS_FREE_DOMAINS = {
    "tempmail.com", "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "throwam.com", "yopmail.com", "sharklasers.com", "trashmail.com",
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _extract_email_address(header_val: str) -> str:
    """Pull bare address from 'Display Name <addr@domain.com>'."""
    m = re.search(r'<([^>]+)>', header_val or "")
    return m.group(1).strip().lower() if m else (header_val or "").strip().lower()


def _domain_of(address: str) -> str:
    parts = address.split("@")
    return parts[-1].lower() if len(parts) == 2 else ""


def _check_auth_headers(msg) -> dict:
    """
    Parse Authentication-Results header for SPF, DKIM, DMARC.
    Returns dict with keys: spf, dkim, dmarc (values: 'pass'|'fail'|'softfail'|'none'|'unknown').
    """
    auth_raw = msg.get("Authentication-Results", "") or ""
    auth_raw = auth_raw.lower()

    def _find(key):
        pattern = re.compile(rf'{key}=(\w+)')
        m = pattern.search(auth_raw)
        return m.group(1) if m else "none"

    return {
        "spf":   _find("spf"),
        "dkim":  _find("dkim"),
        "dmarc": _find("dmarc"),
    }


def _extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get("Content-Disposition", ""))
            if ctype in ("text/plain", "text/html") and "attachment" not in cdispo:
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")
    return body


def _get_attachments(msg) -> list[dict]:
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        attachments.append({
            "filename": filename,
            "extension": ext,
            "is_dangerous": ext in DANGEROUS_EXTENSIONS,
            "content_type": part.get_content_type(),
        })
    return attachments


def _score_urgency(text: str) -> tuple[int, list[str]]:
    """Returns (count_of_urgency_words, list_of_found_words)."""
    lower = text.lower()
    found = [w for w in URGENCY_WORDS if w in lower]
    return len(found), list(set(found))


def _analyze_links(urls: list[str]) -> dict:
    """Categorize extracted URLs."""
    suspicious_links = []
    login_links = []
    short_links = []
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "rebrand.ly", "cutt.ly", "buff.ly", "shorturl.at"}

    for url in urls:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower().lstrip("www.")

            # URL shortener
            if any(netloc == s or netloc.endswith("." + s) for s in shorteners):
                short_links.append(url)

            # Login/credential harvesting path
            path_q = (parsed.path + "?" + parsed.query).lower()
            if any(kw in path_q for kw in ["login", "signin", "verify", "account",
                                             "password", "secure", "update", "confirm"]):
                login_links.append(url)

            # IP-based URLs
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc.split(":")[0]):
                suspicious_links.append({"url": url, "reason": "IP address host"})

            # Punycode / IDN
            if "xn--" in netloc:
                suspicious_links.append({"url": url, "reason": "Punycode/IDN domain (visual spoofing)"})

        except Exception:
            pass

    return {
        "total": len(urls),
        "login_harvesting": login_links[:5],
        "url_shorteners": short_links[:5],
        "suspicious": suspicious_links[:5],
    }


# ── Main entry point ─────────────────────────────────────────────────────────

def analyze_email(file_content: bytes) -> dict:
    """
    Full phishing analysis of a raw .eml file.

    Returns a structured dict with:
      - headers (from, to, subject, date, message_id)
      - auth_results (spf, dkim, dmarc)
      - sender_analysis (spoofing checks)
      - body_preview
      - extracted_urls
      - link_analysis
      - attachments
      - urgency_signals
      - risk_score  (0–100)
      - verdict     (SAFE | SUSPICIOUS | DANGER)
      - verdict_reason  (plain-English summary)
      - findings    (list of specific issues found)
    """
    msg = email.message_from_bytes(file_content, policy=default)

    # ── Headers ─────────────────────────────────────────────────────────────
    from_raw   = msg.get("From", "")
    reply_raw  = msg.get("Reply-To", "")
    subject    = msg.get("Subject", "(No Subject)")
    date_val   = msg.get("Date", "")
    msg_id     = msg.get("Message-ID", "")
    to_val     = msg.get("To", "")
    received   = msg.get_all("Received") or []

    from_addr  = _extract_email_address(from_raw)
    from_domain = _domain_of(from_addr)
    reply_addr = _extract_email_address(reply_raw) if reply_raw else ""
    reply_domain = _domain_of(reply_addr) if reply_addr else ""

    # ── Authentication ───────────────────────────────────────────────────────
    auth = _check_auth_headers(msg)

    # ── Body + URLs ──────────────────────────────────────────────────────────
    body = _extract_body(msg)
    all_urls = list(dict.fromkeys(URL_REGEX.findall(body)))  # deduplicated, order-preserved
    link_analysis = _analyze_links(all_urls)

    # ── Attachments ──────────────────────────────────────────────────────────
    attachments = _get_attachments(msg)
    dangerous_attachments = [a for a in attachments if a["is_dangerous"]]

    # ── Urgency / social engineering ─────────────────────────────────────────
    urgency_count, urgency_words = _score_urgency(subject + " " + body)

    # ── Sender spoofing checks ───────────────────────────────────────────────
    sender_issues = []

    # Display name contains a legitimate brand but domain doesn't match
    display_name_lower = from_raw.lower()
    known_brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix",
                    "bank", "chase", "wells fargo", "citibank", "irs", "fedex",
                    "dhl", "ups", "facebook", "instagram", "twitter"]
    brand_in_name = next((b for b in known_brands if b in display_name_lower), None)
    if brand_in_name and brand_in_name not in from_domain:
        sender_issues.append(f"Display name mentions '{brand_in_name}' but sender domain is '{from_domain}'")

    # Reply-To mismatch
    if reply_addr and reply_domain and reply_domain != from_domain:
        sender_issues.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})")

    # Disposable / temporary email
    if from_domain in SUSPICIOUS_FREE_DOMAINS:
        sender_issues.append(f"Sender uses a disposable/temporary email service ({from_domain})")

    # Free email for what appears to be business context
    if from_domain in SAFE_FREE_DOMAINS and brand_in_name:
        sender_issues.append(f"Legitimate organization would not send from a free email ({from_domain})")

    # ── Risk scoring ─────────────────────────────────────────────────────────
    score = 0
    findings = []

    # Authentication failures (biggest red flags)
    if auth["spf"] in ("fail", "softfail"):
        score += 25
        findings.append(f"❌ SPF {auth['spf'].upper()}: The sender's mail server is NOT authorized to send on behalf of this domain. Strong sign of spoofing.")
    elif auth["spf"] == "none":
        score += 10
        findings.append("⚠️ SPF: No SPF record found — domain has no protection against email spoofing.")

    if auth["dkim"] == "fail":
        score += 20
        findings.append("❌ DKIM FAIL: Email signature is invalid — the email was tampered with or forged.")
    elif auth["dkim"] == "none":
        score += 8
        findings.append("⚠️ DKIM: No digital signature on this email.")

    if auth["dmarc"] == "fail":
        score += 15
        findings.append("❌ DMARC FAIL: This email failed the domain's anti-phishing policy check.")
    elif auth["dmarc"] == "none":
        score += 5
        findings.append("⚠️ DMARC: No DMARC policy set on sender domain.")

    # Sender spoofing
    for issue in sender_issues:
        score += 20
        findings.append(f"🚨 Sender spoofing: {issue}")

    # Urgency language
    if urgency_count >= 5:
        score += 20
        findings.append(f"🚨 High-pressure language detected ({urgency_count} urgency phrases): {', '.join(urgency_words[:5])}")
    elif urgency_count >= 2:
        score += 10
        findings.append(f"⚠️ Urgency/scare language detected: {', '.join(urgency_words[:3])}")

    # Dangerous attachments
    if dangerous_attachments:
        score += 30
        names = ", ".join(a["filename"] for a in dangerous_attachments[:3])
        findings.append(f"🚨 Dangerous attachment(s): {names} — these file types are commonly used to spread malware.")

    # Suspicious links
    if link_analysis["login_harvesting"]:
        score += 15
        findings.append(f"⚠️ {len(link_analysis['login_harvesting'])} link(s) lead to login/account pages — could be credential harvesting.")

    if link_analysis["url_shorteners"]:
        score += 10
        findings.append(f"⚠️ {len(link_analysis['url_shorteners'])} shortened URL(s) hide the real destination.")

    if link_analysis["suspicious"]:
        score += 15
        reasons = "; ".join(f"{s['reason']}" for s in link_analysis["suspicious"][:2])
        findings.append(f"🚨 Suspicious links found: {reasons}")

    score = min(score, 100)

    # ── Verdict ──────────────────────────────────────────────────────────────
    if score >= 65:
        verdict = "DANGER"
        verdict_emoji = "🚫"
        verdict_color = "danger"
        verdict_reason = (
            "⛔ DO NOT open any links or attachments in this email. "
            "This email shows strong signs of being a phishing attack designed to steal your information "
            "or infect your device. Delete it immediately."
        )
    elif score >= 35:
        verdict = "SUSPICIOUS"
        verdict_emoji = "⚠️"
        verdict_color = "suspicious"
        verdict_reason = (
            "⚠️ Be very careful with this email. "
            "It has some warning signs of phishing. Do not click any links or open attachments "
            "unless you can independently verify the sender is genuine (e.g., call them directly)."
        )
    else:
        verdict = "LIKELY SAFE"
        verdict_emoji = "✅"
        verdict_color = "safe"
        verdict_reason = (
            "✅ This email appears to be legitimate based on technical checks. "
            "However, always be cautious — if something feels off, trust your instincts."
        )

    # ── Good signs ───────────────────────────────────────────────────────────
    good_signs = []
    if auth["spf"] == "pass":
        good_signs.append("✅ SPF PASS: Sender's mail server is verified and authorized.")
    if auth["dkim"] == "pass":
        good_signs.append("✅ DKIM PASS: Email has a valid digital signature — not tampered with.")
    if auth["dmarc"] == "pass":
        good_signs.append("✅ DMARC PASS: Email passed the domain's anti-phishing policy.")
    if not dangerous_attachments and attachments:
        good_signs.append("✅ No dangerous attachment types found.")
    if not sender_issues:
        good_signs.append("✅ Sender address looks authentic (no spoofing patterns detected).")

    sender_investigation = None
    if from_addr:
        try:
            from app.modules.email_analysis.investigator import investigate_email_address
            sender_investigation = investigate_email_address(from_addr)
        except Exception:
            pass

    return {
        "headers": {
            "subject": subject,
            "from": from_raw,
            "to": to_val,
            "date": date_val,
            "message_id": msg_id,
            "from_email_id": from_addr,
            "to_email_id": _extract_email_address(to_val),
            "reply_to_email_id": reply_addr or None,
        },
        "sender_email_id_investigation": sender_investigation,
        "auth_results": auth,
        "sender_analysis": {
            "from_address": from_addr,
            "email_id": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_addr or None,
            "reply_domain": reply_domain or None,
            "issues": sender_issues,
        },
        "body_preview": body[:800] + ("…" if len(body) > 800 else ""),
        "extracted_urls": all_urls[:20],
        "link_analysis": link_analysis,
        "attachments": attachments,
        "dangerous_attachments": dangerous_attachments,
        "urgency_signals": {
            "count": urgency_count,
            "words_found": urgency_words[:10],
        },
        "risk_score": score,
        "verdict": verdict,
        "verdict_emoji": verdict_emoji,
        "verdict_color": verdict_color,
        "verdict_reason": verdict_reason,
        "findings": findings,
        "good_signs": good_signs,
    }
