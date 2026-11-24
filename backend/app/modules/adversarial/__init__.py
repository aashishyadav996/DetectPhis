"""
Adversarial URL Mutation Testing module.
Generates evasive mutation variants (homoglyphs, typosquatting, subdomain nesting,
at-sign masking, keyword padding) and evaluates engine resilience.
"""
from app.modules.adversarial.models import (
    MutatedCandidate,
    AdversarialTestReport,
    MutationTechnique,
)
from app.modules.adversarial.generator import generate_mutations
from app.modules.adversarial.evaluator import evaluate_adversarial_resilience

__all__ = [
    "MutatedCandidate",
    "AdversarialTestReport",
    "MutationTechnique",
    "generate_mutations",
    "evaluate_adversarial_resilience",
]
