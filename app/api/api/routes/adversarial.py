"""
Adversarial testing API routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.modules.adversarial.evaluator import evaluate_adversarial_resilience

router = APIRouter(prefix="/api/v1/adversarial", tags=["adversarial"])


class AdversarialTestRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to test with adversarial mutations")


@router.post("/test")
def test_adversarial_resilience(payload: AdversarialTestRequest) -> dict:
    try:
        report = evaluate_adversarial_resilience(payload.url)
        return report.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Adversarial testing failed: {exc}")
