"""
Scan history and forensic reporting API routes.
"""
from typing import Any
from fastapi import APIRouter, HTTPException, Response

from app.database.repository import (
    get_recent_scans,
    get_scan_by_id,
    clear_all_scans,
)
from app.modules.reports.generator import (
    generate_investigation_report_html,
    generate_investigation_report_json,
)

router = APIRouter(prefix="/api/v1", tags=["history", "reports"])


@router.get("/history")
def list_scan_history(limit: int = 50) -> list[dict[str, Any]]:
    return get_recent_scans(limit=limit)


@router.get("/history/{scan_id}")
def get_historical_scan(scan_id: int) -> dict[str, Any]:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation scan not found.")
    return scan


@router.delete("/history")
def delete_all_history() -> dict[str, Any]:
    count = clear_all_scans()
    return {"status": "ok", "deleted_count": count}


@router.get("/reports/{scan_id}/html")
def export_report_html(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation scan not found.")

    html_content = generate_investigation_report_html(scan)
    return Response(content=html_content, media_type="text/html")


@router.get("/reports/{scan_id}/json")
def export_report_json(scan_id: int) -> dict[str, Any]:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation scan not found.")

    return generate_investigation_report_json(scan)


@router.post("/reports/export/html")
def export_live_report_html(payload: dict[str, Any]):
    try:
        html_content = generate_investigation_report_html(payload)
        return Response(content=html_content, media_type="text/html")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {exc}")
