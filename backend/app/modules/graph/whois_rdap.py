"""
WHOIS and RDAP (Registration Data Access Protocol) client.
Queries free, open ICANN-compliant RDAP endpoints (RFC 7480/7484)
to extract domain age, registrar details, registration/expiration dates,
and authoritative nameservers with local file caching and graceful fallback.
"""
import json
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

RDAP_BOOTSTRAP_URL = "https://rdap.org/domain"
CACHE_FILE = Path(__file__).parent / "_rdap_cache.json"
CACHE_TTL_SECONDS = 60 * 60 * 24  # 24 hours for domain registration data


@dataclass
class DomainRegistrationInfo:
    available: bool
    domain: str
    registrar: str | None = None
    created_date: str | None = None
    expiration_date: str | None = None
    updated_date: str | None = None
    age_days: int | None = None
    is_recently_registered: bool = False  # < 30 days old
    is_critically_young: bool = False  # < 14 days old
    nameservers: list[str] = field(default_factory=list)
    status_codes: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_cache() -> dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def _parse_iso_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    cleaned = date_str.replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None


def _parse_rdap_response(domain: str, data: dict[str, Any]) -> DomainRegistrationInfo:
    registrar = None
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles or "registrant" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                        registrar = str(prop[3])
                        break
            if not registrar and entity.get("handle"):
                registrar = entity.get("handle")
            if registrar:
                break

    created_date_str = None
    expiration_date_str = None
    updated_date_str = None

    events = data.get("events", [])
    for event in events:
        action = event.get("eventAction")
        date_val = event.get("eventDate")
        if action == "registration":
            created_date_str = date_val
        elif action == "expiration":
            expiration_date_str = date_val
        elif action in ("last changed", "last update"):
            updated_date_str = date_val

    age_days = None
    is_recently_registered = False
    is_critically_young = False

    if created_date_str:
        dt = _parse_iso_date(created_date_str)
        if dt:
            now = datetime.now(timezone.utc)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            diff = (now - dt).days
            if diff >= 0:
                age_days = diff
                is_recently_registered = age_days <= 30
                is_critically_young = age_days <= 14

    nameservers = []
    for ns in data.get("nameservers", []):
        ldh = ns.get("ldhName")
        if ldh:
            nameservers.append(ldh.lower())

    status_codes = data.get("status", [])

    return DomainRegistrationInfo(
        available=True,
        domain=domain,
        registrar=registrar or "Unknown Registrar",
        created_date=created_date_str,
        expiration_date=expiration_date_str,
        updated_date=updated_date_str,
        age_days=age_days,
        is_recently_registered=is_recently_registered,
        is_critically_young=is_critically_young,
        nameservers=nameservers,
        status_codes=status_codes,
    )


def get_domain_registration_info(domain: str, timeout_seconds: float = 3.0) -> DomainRegistrationInfo:
    """
    Fetches domain registration data via RDAP with caching and graceful error handling.
    """
    if not domain or domain.replace(".", "").isdigit():
        return DomainRegistrationInfo(
            available=False,
            domain=domain or "",
            error="Input is not a domain name (raw IP or empty).",
        )

    cache = _load_cache()
    cached_entry = cache.get(domain)
    if cached_entry and (time.time() - cached_entry.get("fetched_at", 0)) < CACHE_TTL_SECONDS:
        cached_data = cached_entry.get("info", {})
        return DomainRegistrationInfo(**cached_data)

    url = f"{RDAP_BOOTSTRAP_URL}/{domain}"
    headers = {
        "User-Agent": "PhishTrace-AI/1.0 (Cybersecurity Research Platform)",
        "Accept": "application/rdap+json, application/json",
    }

    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            response = client.get(url, headers=headers)
            if response.status_code == 200:
                info = _parse_rdap_response(domain, response.json())
                cache[domain] = {"fetched_at": time.time(), "info": asdict(info)}
                _save_cache(cache)
                return info
            elif response.status_code == 404:
                return DomainRegistrationInfo(
                    available=False,
                    domain=domain,
                    error="Domain not found in RDAP registry (may be unregistered or unsupported TLD).",
                )
            else:
                return DomainRegistrationInfo(
                    available=False,
                    domain=domain,
                    error=f"RDAP query returned HTTP {response.status_code}.",
                )
    except httpx.TimeoutException:
        return DomainRegistrationInfo(
            available=False,
            domain=domain,
            error="RDAP query timed out.",
        )
    except httpx.RequestError as exc:
        return DomainRegistrationInfo(
            available=False,
            domain=domain,
            error=f"RDAP query failed: {exc}",
        )
    except Exception as exc:
        return DomainRegistrationInfo(
            available=False,
            domain=domain,
            error=f"Unexpected RDAP error: {exc}",
        )
