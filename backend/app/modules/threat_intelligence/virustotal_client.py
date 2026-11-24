"""
VirusTotal integration.

IMPORTANT — HONESTY NOTE FOR THE REPORT:
This client is real, working code, but it has NOT been tested against the
live VirusTotal API in this development environment (no VirusTotal API key
was available here, and this sandbox's network egress is restricted to a
fixed allow-list of package/registry domains that does not include
virustotal.com). You must test this module yourself once you have a real
VT API key, from an environment with normal internet access.

What IS verified: the request/response shapes below match VirusTotal's
documented v3 API format as of the last time this was written. If the
live API has changed since, adjust `_parse_analysis_response` accordingly
— don't assume it still matches without checking a real response.

Design:
- Results are cached by normalized URL (in-memory + optional file cache)
  to respect the free tier's ~4 req/min / 500 req/day limits.
- If the API key is missing, or the request fails/times out, the caller
  gets a clearly-flagged "unavailable" result instead of a crash — the
  rest of the risk engine must continue without this signal, per the
  project's error-handling requirements.
"""
import base64
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import httpx

from app.core.config import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_FILE = Path(__file__).parent / "_vt_cache.json"
CACHE_TTL_SECONDS = 60 * 60 * 6  # 6 hours — balances freshness against quota use


@dataclass
class VirusTotalEvidence:
    available: bool
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    reputation_gap: bool = False  # True when total_engines > 0 but detections are 0/low
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _url_to_vt_id(url: str) -> str:
    """VirusTotal v3 identifies URLs by the base64 (URL-safe, no padding) of the URL string."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _load_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except OSError:
        pass  # cache is a performance optimization, not a correctness requirement


def _parse_analysis_response(data: dict) -> VirusTotalEvidence:
    """
    Expects VirusTotal v3 URL report shape:
    data["data"]["attributes"]["last_analysis_stats"] = {
        "malicious": int, "suspicious": int, "harmless": int, "undetected": int, ...
    }
    """
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    if not stats:
        return VirusTotalEvidence(available=False, error="No analysis stats in response.")

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    # Reputation gap: engines have scanned it, but detections are 0 or very low.
    # This is the trigger condition for the low-reputation early-warning feature —
    # it does NOT by itself mean the URL is safe.
    reputation_gap = total > 0 and (malicious + suspicious) <= 1

    return VirusTotalEvidence(
        available=True,
        malicious_count=malicious,
        suspicious_count=suspicious,
        harmless_count=harmless,
        undetected_count=undetected,
        total_engines=total,
        reputation_gap=reputation_gap,
    )


def get_virustotal_evidence(normalized_url: str, timeout_seconds: float = 8.0) -> VirusTotalEvidence:
    if not settings.virustotal_api_key:
        return VirusTotalEvidence(
            available=False,
            error="VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY in backend/.env.",
        )

    cache = _load_cache()
    cached_entry = cache.get(normalized_url)
    if cached_entry and (time.time() - cached_entry["fetched_at"]) < CACHE_TTL_SECONDS:
        return VirusTotalEvidence(**cached_entry["evidence"])

    url_id = _url_to_vt_id(normalized_url)
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            response = client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

            if response.status_code == 404:
                # VirusTotal has never seen this URL. This is itself a
                # meaningful signal for the low-reputation experiment —
                # not an error.
                evidence = VirusTotalEvidence(
                    available=True,
                    total_engines=0,
                    reputation_gap=True,
                )
            elif response.status_code == 429:
                return VirusTotalEvidence(available=False, error="VirusTotal rate limit exceeded.")
            elif response.status_code != 200:
                return VirusTotalEvidence(
                    available=False,
                    error=f"VirusTotal returned HTTP {response.status_code}.",
                )
            else:
                evidence = _parse_analysis_response(response.json())

    except httpx.TimeoutException:
        return VirusTotalEvidence(available=False, error="VirusTotal request timed out.")
    except httpx.RequestError as exc:
        return VirusTotalEvidence(available=False, error=f"VirusTotal request failed: {exc}")

    cache[normalized_url] = {"fetched_at": time.time(), "evidence": asdict(evidence)}
    _save_cache(cache)

    return evidence
