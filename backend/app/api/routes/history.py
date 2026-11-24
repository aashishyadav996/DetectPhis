"""
Scan history and forensic reporting Flask Blueprint.
"""
from flask import Blueprint, jsonify, abort, Response

from app.database.repository import (
    get_recent_scans,
    get_scan_by_id,
    clear_all_scans,
)
from app.modules.reports.generator import (
    generate_investigation_report_html,
    generate_investigation_report_json,
)

history_bp = Blueprint("history", __name__, url_prefix="/api/v1")


@history_bp.route("/history", methods=["GET"])
def list_scan_history():
    from flask import request
    try:
        limit = int(request.args.get("limit", 50))
    except ValueError:
        limit = 50
    return jsonify(get_recent_scans(limit=limit)), 200


@history_bp.route("/history/<int:scan_id>", methods=["GET"])
def get_historical_scan(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Investigation scan not found.")
    return jsonify(scan), 200


@history_bp.route("/history", methods=["DELETE"])
def delete_all_history():
    count = clear_all_scans()
    return jsonify({"status": "ok", "deleted_count": count}), 200


@history_bp.route("/reports/<int:scan_id>/html", methods=["GET"])
def export_report_html(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Investigation scan not found.")
    html_content = generate_investigation_report_html(scan)
    return Response(html_content, status=200, mimetype="text/html")


@history_bp.route("/reports/<int:scan_id>/json", methods=["GET"])
def export_report_json(scan_id: int):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404, description="Investigation scan not found.")
    return jsonify(generate_investigation_report_json(scan)), 200


@history_bp.route("/reports/export/html", methods=["POST"])
def export_live_report_html():
    from flask import request
    payload = request.get_json(silent=True)
    if not payload:
        abort(400, description="JSON body required.")
    try:
        html_content = generate_investigation_report_html(payload)
        return Response(html_content, status=200, mimetype="text/html")
    except Exception as exc:
        abort(500, description=f"Failed to generate report: {exc}")
