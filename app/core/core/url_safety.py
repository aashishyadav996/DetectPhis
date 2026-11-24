"""
URL normalization and basic SSRF-safety checks.

IMPORTANT: This module currently only validates and normalizes the URL
string for feature extraction — it does NOT fetch the URL's content yet.
Once live fetching (e.g. redirect-following, screenshot capture) is added
in a later phase, this module must be extended with:
  - private/loopback/link-local IP blocking after DNS resolution
  - cloud metadata endpoint blocking (169.254.169.254, etc.)
  - scheme allow-listing (http/https only)
  - redirect chain re-validation at every hop

Do not assume this file alone is sufficient SSRF protection once fetching
is implemented — flagged here so it isn't forgotten in Phase 3/5.
"""
from urllib.parse import urlparse, urlunparse

ALLOWED_SCHEMES = {"http", "https"}


class InvalidURLError(ValueError):
    pass


def normalize_url(raw_url: str) -> str:
    """
    Normalize a submitted URL string: trim whitespace, enforce an allowed
    scheme, lowercase the scheme/host, and reject obviously malformed input.
    """
    if not raw_url or not raw_url.strip():
        raise InvalidURLError("URL must not be empty.")

    candidate = raw_url.strip()

    # If no scheme was provided, assume https rather than silently guessing.
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidURLError(f"Unsupported URL scheme: {parsed.scheme!r}")

    if not parsed.netloc:
        raise InvalidURLError("URL is missing a valid host.")

    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        "",  # strip fragment — not relevant to server-side analysis
    ))
    return normalized
