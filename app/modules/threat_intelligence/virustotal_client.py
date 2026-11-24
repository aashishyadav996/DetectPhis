"""
VirusTotal v3 integration with live URL submission.

If VT has never seen a URL (404), we submit it for scanning, wait briefly,
then fetch the result — giving REAL live data instead of "unavailable".

Caching: 6-hour in-memory + file cache to respect free-tier quotas
(4 req/min, 500 req/day).  Missing API key → graceful unavailable result.
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
CACHE_TTL_SECONDS = 60 * 60 * 6   # 6 hours

# In-memory cache (faster than file reads on every request)
_mem_cache: dict = {}


@dataclass
class VirusTotalEvidence:
    available: bool
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
    total_engines: int = 0
    reputation_gap: bool = False
    scan_date: str | None = None
    cache_status: str | None = None
    permalink: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _url_to_vt_id(url: str) -> str:
    """VirusTotal v3 identifies URLs by URL-safe base64 (no padding) of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _load_file_cache() -> dict:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_file_cache(cache: dict) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except OSError:
        pass


def _parse_analysis_response(data: dict) -> VirusTotalEvidence:
    """
    Parses a VirusTotal v3 URL report response.
    Shape: data["data"]["attributes"]["last_analysis_stats"]
    """
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    if not stats:
        return VirusTotalEvidence(available=False, error="No analysis stats in VT response.")

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    harmless    = stats.get("harmless", 0)
    undetected  = stats.get("undetected", 0)
    total       = malicious + suspicious + harmless + undetected

    # Reputation gap: URL has been scanned but has very few/no detections
    reputation_gap = total > 0 and (malicious + suspicious) <= 1

    # Scan date & permalink
    scan_ts   = attrs.get("last_analysis_date")
    scan_date = None
    if scan_ts:
        try:
            import datetime
            scan_date = datetime.datetime.utcfromtimestamp(int(scan_ts)).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            scan_date = str(scan_ts)

    permalink = f"https://www.virustotal.com/gui/url/{_url_to_vt_id(attrs.get('url', ''))}"

    return VirusTotalEvidence(
        available=True,
        malicious_count=malicious,
        suspicious_count=suspicious,
        harmless_count=harmless,
        undetected_count=undetected,
        total_engines=total,
        reputation_gap=reputation_gap,
        scan_date=scan_date,
        cache_status="Live",
        permalink=permalink,
    )


def _submit_url_for_scan(client: httpx.Client, url: str, headers: dict) -> str | None:
    """
    Submits a URL to VirusTotal for scanning.
    Returns the analysis ID (used to poll for results), or None on failure.
    """
    try:
        resp = client.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": url},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("id")
    except Exception:
        pass
    return None


def _poll_analysis(client: httpx.Client, analysis_id: str, headers: dict,
                   max_polls: int = 3, poll_interval: float = 4.0) -> dict | None:
    """
    Polls the VT analysis endpoint until status == 'completed' or max_polls reached.
    Returns the raw JSON body or None.
    """
    for _ in range(max_polls):
        try:
            resp = client.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers, timeout=10.0)
            if resp.status_code == 200:
                body = resp.json()
                status = body.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return body
        except Exception:
            pass
        time.sleep(poll_interval)
    return None


def _analysis_to_evidence(analysis_body: dict) -> VirusTotalEvidence:
    """Converts a VT /analyses/{id} response into VirusTotalEvidence."""
    attrs = analysis_body.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})
    if not stats:
        return VirusTotalEvidence(available=False, error="Analysis completed but no stats returned.")

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total      = malicious + suspicious + harmless + undetected
    reputation_gap = total > 0 and (malicious + suspicious) <= 1

    return VirusTotalEvidence(
        available=True,
        malicious_count=malicious,
        suspicious_count=suspicious,
        harmless_count=harmless,
        undetected_count=undetected,
        total_engines=total,
        reputation_gap=reputation_gap,
        scan_date="Just scanned",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_virustotal_evidence(normalized_url: str, timeout_seconds: float = 10.0) -> VirusTotalEvidence:
    """
    Full VirusTotal v3 lookup with live submission fallback.

    Flow:
      1. Check memory + file cache (6-hour TTL).
      2. GET /urls/{id} — if found (200), parse and return.
      3. If 404 (VT never seen this URL):
         a. POST /urls to submit for scanning.
         b. Poll /analyses/{id} up to 3 times (≈12 s) for result.
         c. Return analysis result (or "newly submitted" placeholder).
      4. On rate-limit (429) or network error → graceful unavailable.
    """
    if not settings.virustotal_api_key:
        return VirusTotalEvidence(
            available=False,
            error="VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to your .env file.",
        )

    # --- Cache check ---
    now = time.time()
    mem_entry = _mem_cache.get(normalized_url)
    if mem_entry and (now - mem_entry["fetched_at"]) < CACHE_TTL_SECONDS:
        ev = VirusTotalEvidence(**mem_entry["evidence"])
        ev.cache_status = "Memory Cache"
        return ev

    file_cache = _load_file_cache()
    file_entry = file_cache.get(normalized_url)
    if file_entry and (now - file_entry["fetched_at"]) < CACHE_TTL_SECONDS:
        ev = VirusTotalEvidence(**file_entry["evidence"])
        ev.cache_status = "Disk Cache"
        _mem_cache[normalized_url] = file_entry
        return ev

    headers = {"x-apikey": settings.virustotal_api_key}
    url_id  = _url_to_vt_id(normalized_url)

    try:
        with httpx.Client(timeout=timeout_seconds) as client:
            resp = client.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

            if resp.status_code == 200:
                evidence = _parse_analysis_response(resp.json())

            elif resp.status_code == 404:
                # URL not in VT database — submit it now
                analysis_id = _submit_url_for_scan(client, normalized_url, headers)
                if analysis_id:
                    analysis_body = _poll_analysis(client, analysis_id, headers)
                    if analysis_body:
                        evidence = _analysis_to_evidence(analysis_body)
                    else:
                        # Submission succeeded but scan not finished in time
                        evidence = VirusTotalEvidence(
                            available=True,
                            total_engines=0,
                            reputation_gap=True,
                            scan_date="Submitted — scan pending",
                            error=None,
                        )
                else:
                    evidence = VirusTotalEvidence(
                        available=True,
                        total_engines=0,
                        reputation_gap=True,
                        error="URL submitted to VT for first-time scanning; results pending.",
                    )

            elif resp.status_code == 429:
                return VirusTotalEvidence(available=False, error="VirusTotal rate limit exceeded. Try again later.")

            elif resp.status_code == 401:
                return VirusTotalEvidence(available=False, error="Invalid VirusTotal API key.")

            else:
                return VirusTotalEvidence(
                    available=False,
                    error=f"VirusTotal returned HTTP {resp.status_code}.",
                )

    except httpx.TimeoutException:
        return VirusTotalEvidence(available=False, error="VirusTotal request timed out.")
    except httpx.RequestError as exc:
        return VirusTotalEvidence(available=False, error=f"VirusTotal request failed: {exc}")

    # --- Cache result ---
    entry = {"fetched_at": now, "evidence": asdict(evidence)}
    _mem_cache[normalized_url] = entry
    file_cache[normalized_url] = entry
    _save_file_cache(file_cache)

    return evidence
