"""
Adversarial testing Flask Blueprint.
"""
from flask import Blueprint, request, jsonify, abort

from app.modules.adversarial.evaluator import evaluate_adversarial_resilience

adversarial_bp = Blueprint("adversarial", __name__, url_prefix="/api/v1/adversarial")


@adversarial_bp.route("/test", methods=["POST"])
def test_adversarial_resilience():
    body = request.get_json(silent=True)
    if not body or not body.get("url"):
        abort(400, description="Missing required field: url")

    url_input = body["url"].strip()
    if not url_input or len(url_input) > 2048:
        abort(400, description="URL must be between 1 and 2048 characters.")

    try:
        report = evaluate_adversarial_resilience(url_input)
        return jsonify(report.to_dict()), 200
    except Exception as exc:
        abort(500, description=f"Adversarial testing failed: {exc}")
