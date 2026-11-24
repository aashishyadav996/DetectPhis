"""
Data models for Adversarial URL Mutation Testing.
"""
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any


class MutationTechnique(str, Enum):
    HOMOGLYPH_SUBSTITUTION = "Homoglyph / Visual Lookalike"
    TYPOSQUATTING_OMISSION = "Typosquatting (Character Omission)"
    TYPOSQUATTING_REPETITION = "Typosquatting (Character Duplication)"
    TYPOSQUATTING_TRANSPOSITION = "Typosquatting (Character Transposition)"
    SUBDOMAIN_NESTING = "Subdomain Nesting & Brand Masquerading"
    AT_SIGN_DESTINATION_MASK = "Userinfo '@' Destination Masking"
    AUTH_KEYWORD_PADDING = "Authentication Keyword Hyphenation"
    TLD_SWAP = "Alternative TLD Substitution"


@dataclass
class MutatedCandidate:
    technique: str
    mutated_url: str
    description: str
    risk_score: int
    classification: str
    detected: bool  # True if engine correctly flagged as Suspicious or High Risk (>= 45)
    evasion_success: bool  # True if mutation slipped through as Low Risk (< 45)
    key_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AdversarialTestReport:
    original_url: str
    baseline_risk_score: int
    total_mutations: int
    detected_count: int
    evaded_count: int
    resilience_rate_percent: float  # (detected_count / total_mutations) * 100
    mutations: list[MutatedCandidate] = field(default_factory=list)
    vulnerability_summary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_url": self.original_url,
            "baseline_risk_score": self.baseline_risk_score,
            "total_mutations": self.total_mutations,
            "detected_count": self.detected_count,
            "evaded_count": self.evaded_count,
            "resilience_rate_percent": round(self.resilience_rate_percent, 1),
            "mutations": [m.to_dict() for m in self.mutations],
            "vulnerability_summary": self.vulnerability_summary,
        }
