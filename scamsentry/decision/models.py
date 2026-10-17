"""Typed Stage 3 decision result and traceable signals."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from scamsentry.ai.schemas import Uncertainty
from scamsentry.models import AnalysisStatus, RiskBand

DECISION_SCHEMA_VERSION = "1.0"
RISK_POLICY_VERSION = "1.0"


class SignalSource(str, Enum):
    STAGE1 = "stage1"
    STAGE2 = "stage2"


class RecommendationPriority(str, Enum):
    IMMEDIATE = "immediate"
    SOON = "soon"
    ROUTINE = "routine"


@dataclass(frozen=True)
class DecisionSignal:
    """A fused signal preserving its origin and any Stage 1 finding reference."""

    signal_id: str
    source: SignalSource
    category: str
    reference_id: str | None
    severity: str | None
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "source": self.source.value,
            "category": self.category,
            "reference_id": self.reference_id,
            "severity": self.severity,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class Recommendation:
    """A defensive action and the evidence supporting its relevance."""

    action_id: str
    action: str
    reason: str
    supporting_finding_ids: tuple[str, ...]
    priority: RecommendationPriority

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action,
            "reason": self.reason,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "priority": self.priority.value,
        }


@dataclass(frozen=True)
class DecisionResult:
    """Stage 3 output; original Stage 1 and Stage 2 results are not embedded."""

    final_risk_band: RiskBand
    stage1_status: AnalysisStatus
    stage1_risk_band: RiskBand | None
    ai_status: str
    rationale: str
    policy_rules: tuple[str, ...]
    supporting_finding_ids: tuple[str, ...]
    signals: tuple[DecisionSignal, ...]
    notes: tuple[str, ...]
    uncertainty: Uncertainty
    uncertainty_reasons: tuple[str, ...]
    recommendations: tuple[Recommendation, ...]
    stage1_preserved: bool = True
    schema_version: str = DECISION_SCHEMA_VERSION
    risk_policy_version: str = RISK_POLICY_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "risk_policy_version": self.risk_policy_version,
            "final_risk_band": self.final_risk_band.value,
            "stage1_status": self.stage1_status.value,
            "stage1_risk_band": (
                None if self.stage1_risk_band is None else self.stage1_risk_band.value
            ),
            "ai_status": self.ai_status,
            "heuristic_score": None,
            "score_type": None,
            "rationale": self.rationale,
            "policy_rules": list(self.policy_rules),
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "signals": [item.to_dict() for item in self.signals],
            "notes": list(self.notes),
            "uncertainty": self.uncertainty.value,
            "uncertainty_reasons": list(self.uncertainty_reasons),
            "recommendations": [item.to_dict() for item in self.recommendations],
            "stage1_preserved": self.stage1_preserved,
        }
