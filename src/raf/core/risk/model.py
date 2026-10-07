"""Explainable risk scoring.

R$F never emits an unexplained number. A score is the clamped sum of named
factors; each factor states its points, its direction (+ raises risk, -
lowers it) and the evidence (object IDs) it is based on. Levels:

    score  < 25  LOW
    25 - 49      MEDIUM
    50 - 74      HIGH
    >= 75        CRITICAL

The factor tables of each model (blast radius, asset exposure) are documented
in docs/risk-model.md together with this methodology version.
"""

from __future__ import annotations

from pydantic import Field

from raf.core.objects.models import RafModel

METHODOLOGY_VERSION = "raf-risk/1.0"
THRESHOLDS = ((75, "CRITICAL"), (50, "HIGH"), (25, "MEDIUM"), (0, "LOW"))


class RiskFactor(RafModel):
    rule: str
    label: str
    sign: str  # "+" raises, "-" lowers
    points: int
    evidence: list[str] = Field(default_factory=list)


class RiskAssessment(RafModel):
    subject: str
    score: int
    level: str
    factors: list[RiskFactor]
    methodology: str = METHODOLOGY_VERSION


def level_for(score: int) -> str:
    for threshold, level in THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"


def assess(subject: str, factors: list[RiskFactor]) -> RiskAssessment:
    raw = sum(f.points if f.sign == "+" else -f.points for f in factors)
    score = max(0, min(100, raw))
    ordered = sorted(factors, key=lambda f: (f.sign != "+", -f.points, f.rule))
    return RiskAssessment(subject=subject, score=score, level=level_for(score), factors=ordered)


def factor(rule: str, label: str, points: int, evidence: list[str] | None = None) -> RiskFactor:
    """Convenience: positive points raise risk, negative points lower it."""
    return RiskFactor(
        rule=rule,
        label=label,
        sign="+" if points >= 0 else "-",
        points=abs(points),
        evidence=sorted(set(evidence or []))[:20],
    )
