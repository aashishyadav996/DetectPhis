"""
Database package for PhishTrace AI.
Supports PostgreSQL (Neon) and persistent SQLite for local development.
"""
from app.database.connection import get_db, init_db
from app.database.models import ScanRecord, Base
from app.database.repository import (
    save_scan_record,
    get_recent_scans,
    get_scan_by_id,
    clear_all_scans,
)

__all__ = [
    "get_db",
    "init_db",
    "ScanRecord",
    "Base",
    "save_scan_record",
    "get_recent_scans",
    "get_scan_by_id",
    "clear_all_scans",
]
