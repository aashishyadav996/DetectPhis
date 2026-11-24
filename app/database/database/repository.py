"""
Database repository queries and persistence functions.
"""
import json
from typing import Any
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal, init_db
from app.database.models import ScanRecord


def save_scan_record(
    url: str,
    normalized_url: str,
    risk_score: int,
    confidence: int,
    classification: str,
    detected_brand: str | None,
    domain: str | None,
    domain_age_days: int | None,
    is_recently_registered: bool,
    ssrf_risk: bool,
    full_response_dict: dict[str, Any],
) -> ScanRecord:
    """
    Persists an investigation result to the database.
    """
    init_db()
    db: Session = SessionLocal()
    try:
        record = ScanRecord(
            url=url,
            normalized_url=normalized_url,
            risk_score=risk_score,
            confidence=confidence,
            classification=classification,
            detected_brand=detected_brand,
            domain=domain,
            domain_age_days=domain_age_days,
            is_recently_registered=is_recently_registered,
            ssrf_risk=ssrf_risk,
            details_json=json.dumps(full_response_dict),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    finally:
        db.close()


def get_recent_scans(limit: int = 50) -> list[dict[str, Any]]:
    """
    Retrieves the most recent investigations.
    """
    init_db()
    db: Session = SessionLocal()
    try:
        records = (
            db.query(ScanRecord)
            .order_by(ScanRecord.created_at.desc(), ScanRecord.id.desc())
            .limit(limit)
            .all()
        )
        return [r.to_dict() for r in records]
    finally:
        db.close()


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    """
    Retrieves a single scan record by ID.
    """
    init_db()
    db: Session = SessionLocal()
    try:
        record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        return record.to_dict() if record else None
    finally:
        db.close()


def clear_all_scans() -> int:
    """
    Clears all scan history.
    """
    init_db()
    db: Session = SessionLocal()
    try:
        deleted = db.query(ScanRecord).delete()
        db.commit()
        return deleted
    finally:
        db.close()
