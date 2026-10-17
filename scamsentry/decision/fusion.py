"""Public Stage 3 decision API."""

from __future__ import annotations

from typing import Any

from scamsentry.ai.schemas import AIAnalysis
from scamsentry.decision.models import (
    DecisionResult,
    RISK_POLICY_VERSION,
    Recommendation,
)
from scamsentry.decision.policy import (
    assess_risk,
    build_recommendations,
    build_signals,
    confidence_uncertainty,
    uncertainty_reasons,
)
from scamsentry.decision.validation import validate_inputs
from scamsentry.models import AnalysisResult


def assess(
    result: AnalysisResult,
    ai_analysis: AIAnalysis | dict[str, Any] | None = None,
    *,
    ai_status: str | None = None,
) -> DecisionResult:
    """Validate and deterministically fuse Stage 1 and optional Stage 2 output.

    Stage 2 contributes explanatory context only; it cannot create evidence,
    alter a finding, or change the risk band.
    """

    validated = validate_inputs(result, ai_analysis, ai_status=ai_status)
    final_band, policy_rules, policy_notes = assess_risk(result, validated.findings)
    notes = list(policy_notes)
    if validated.ai_status == "unavailable":
        notes.append("Stage 2 was unavailable and did not affect the risk assessment.")
    elif validated.ai_status == "invalid":
        notes.append("Stage 2 output was invalid and was excluded from the decision.")
    if validated.ai_analysis is not None:
        notes.append(
            "Stage 2 is advisory context only; it neither creates nor removes Stage 1 evidence."
        )
        if (
            validated.ai_analysis.likely_intent.value == "benign_or_informational"
            and final_band.value in {"REVIEW", "HIGH_CONCERN"}
        ):
            notes.append(
                "Stage 2's benign interpretation conflicts with Stage 1 indicators; "
                "the Stage 1 risk assessment was retained."
            )
        elif (
            validated.ai_analysis.likely_intent.value not in {
                "benign_or_informational",
                "unclear",
            }
            and final_band.value in {"LOW_CONCERN", "INCONCLUSIVE"}
        ):
            notes.append(
                "Stage 2 suggested suspicious intent without supporting Stage 1 findings; "
                "it did not raise the risk band."
            )

    rationale = (
        f"{final_band.value} under risk policy {RISK_POLICY_VERSION}: "
        + "; ".join(policy_rules)
        + ". Stage 2 interpretation is contextual only and never changes this band."
    )
    recommendations: tuple[Recommendation, ...] = build_recommendations(
        final_band, validated.findings
    )
    return DecisionResult(
        final_risk_band=final_band,
        stage1_status=result.analysis_status,
        stage1_risk_band=result.risk_band,
        ai_status=validated.ai_status,
        rationale=rationale,
        policy_rules=policy_rules,
        supporting_finding_ids=tuple(finding.id for finding in validated.findings),
        signals=build_signals(validated.findings, validated.ai_analysis),
        notes=tuple(notes),
        uncertainty=confidence_uncertainty(
            result, validated.ai_analysis, ai_status=validated.ai_status
        ),
        uncertainty_reasons=uncertainty_reasons(
            result, validated.ai_analysis, ai_status=validated.ai_status
        ),
        recommendations=recommendations,
    )
