from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze")


class AnalyzeResponse(BaseModel):
    normalized_url: str
    risk_score: int
    confidence: int
    classification: str
    reasons_increasing: list[str]
    reasons_decreasing: list[str]
    signal_contributions: list[dict]
    reputation_gap_warning: bool
    features: dict
    brand_analysis: dict
    virustotal: dict
    ml: dict
    threat_graph: dict
    scan_id: int | None = None
