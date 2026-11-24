"""
Request/response shape reference (documentation only).
Flask does not use these for validation — kept as a reference for
what /api/v1/analyze returns so the frontend contract is clear.
"""

ANALYZE_REQUEST_FIELDS = {"url": "str (1–2048 chars, required)"}

ANALYZE_RESPONSE_FIELDS = {
    "normalized_url": "str",
    "risk_score": "int",
    "confidence": "int",
    "classification": "str",
    "reasons_increasing": "list[str]",
    "reasons_decreasing": "list[str]",
    "signal_contributions": "list[dict]",
    "reputation_gap_warning": "bool",
    "features": "dict",
    "brand_analysis": "dict",
    "virustotal": "dict",
    "ml": "dict",
    "threat_graph": "dict",
    "scan_id": "int | None",
}
