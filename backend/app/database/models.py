"""
Database ORM models.
"""
from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False)
    normalized_url = Column(String(2048), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    confidence = Column(Integer, nullable=False)
    classification = Column(String(50), nullable=False)
    detected_brand = Column(String(100), nullable=True)
    domain = Column(String(255), nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    is_recently_registered = Column(Boolean, default=False)
    ssrf_risk = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    details_json = Column(Text, nullable=False)

    def to_dict(self) -> dict[str, Any]:
        details = {}
        try:
            details = json.loads(self.details_json) if self.details_json else {}
        except Exception:
            details = {}

        return {
            "id": self.id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "classification": self.classification,
            "detected_brand": self.detected_brand,
            "domain": self.domain,
            "domain_age_days": self.domain_age_days,
            "is_recently_registered": self.is_recently_registered,
            "ssrf_risk": self.ssrf_risk,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "details": details,
        }
