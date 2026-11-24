"""Strict URL normalization for offline phishing analysis.

This module does not fetch submitted URLs. If URL fetching is ever added,
separate SSRF controls must validate every resolved address and redirect hop.
"""
from urllib.parse import urlsplit, urlunsplit
import ipaddress
import re

ALLOWED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 8192
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f\\]")


class InvalidURLError(ValueError):
    """Raised when a submitted URL cannot be safely normalized."""


def normalize_url(raw_url: str) -> str:
    """Validate and normalize an HTTP(S) URL without contacting its host."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise InvalidURLError("URL must not be empty.")

    candidate = raw_url.strip()
    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if _CONTROL_OR_SPACE.search(candidate):
        raise InvalidURLError("URL must not contain whitespace, control characters, or backslashes.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        # Accessing .port validates its syntax and range.
        port = parsed.port
    except ValueError as exc:
        raise InvalidURLError("URL has an invalid host or port.") from exc

    if scheme not in ALLOWED_SCHEMES:
        raise InvalidURLError(f"Unsupported URL scheme: {scheme!r}")
    if not parsed.netloc or not hostname:
        raise InvalidURLError("URL is missing a valid host.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise InvalidURLError("URLs containing embedded credentials are not accepted.")
    if any(ch.isspace() for ch in hostname):
        raise InvalidURLError("URL host is invalid.")

    # Reject malformed numeric IPv4-like hosts while allowing normal domain names
    # and IPv6 literals. The analyzer can still inspect public/private IP literals.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if ":" in hostname:
            raise InvalidURLError("URL host is invalid.")
        if hostname.startswith(".") or ".." in hostname or hostname.endswith(".") and hostname == ".":
            raise InvalidURLError("URL host is invalid.")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", hostname):
            raise InvalidURLError("URL host contains unsupported characters.")

    # Rebuild authority safely. IPv6 hosts must remain bracketed.
    host_text = hostname.lower()
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if ip_obj.version == 6:
            host_text = f"[{host_text}]"
    except ValueError:
        pass
    netloc = host_text + (f":{port}" if port is not None else "")

    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
