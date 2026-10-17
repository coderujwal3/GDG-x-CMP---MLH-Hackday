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
from scamsentry.models import (
    AnalysisResult,
    AnalysisStatus,
    Category,
    Finding,
    RiskBand,
    Severity,
)


def _decision_rationale(
    result: AnalysisResult,
    findings: tuple[Finding, ...],
    *,
    final_band: RiskBand,
    policy_rules: tuple[str, ...],
    ai_status: str,
    uncertainty_reasons: tuple[str, ...],
) -> str:
    stage1_band = (
        "not supplied" if result.risk_band is None else result.risk_band.value
    )
    supporting = ", ".join(
        f"{finding.id} ({finding.category.value}/{finding.severity.value})"
        for finding in findings
    ) or "none"
    parts = [
        f"Risk policy {RISK_POLICY_VERSION}.",
        f"Stage 1 risk band: {stage1_band}; Stage 3 final risk band: {final_band.value}.",
        f"Supporting findings: {supporting}.",
        f"Policy rules applied: {', '.join(policy_rules)}.",
    ]

    if result.analysis_status is not AnalysisStatus.COMPLETE:
        parts.append(
            f"INCONCLUSIVE was selected because Stage 1 status is "
            f"{result.analysis_status.value}, so the deterministic analysis is incomplete."
        )
    elif not findings:
        parts.append(
            "INCONCLUSIVE was selected because no implemented Stage 1 check matched; "
            "absence of findings does not establish safety."
        )
    else:
        strong_categories = {
            finding.category
            for finding in findings
            if finding.severity in {Severity.MEDIUM, Severity.HIGH}
        }
        high_findings = tuple(
            finding for finding in findings if finding.severity is Severity.HIGH
        )
        if strong_categories == {Category.URGENCY, Category.IMPERSONATION}:
            parts.append(
                "REVIEW was selected because urgency and impersonation are correlated "
                "and do not count as independent categories; the HIGH_CONCERN threshold "
                "was not met."
            )
        elif final_band is RiskBand.HIGH_CONCERN:
            high_ids = ", ".join(finding.id for finding in high_findings)
            parts.append(
                f"HIGH_CONCERN was selected because {len(strong_categories)} distinct "
                f"strong categories and at least one HIGH finding ({high_ids}) meet the "
                "policy threshold."
            )
        elif not high_findings:
            parts.append(
                f"REVIEW was selected because no HIGH finding was present among "
                f"{len(strong_categories)} distinct strong categories; HIGH_CONCERN "
                "requires at least two such categories and at least one HIGH finding."
            )
        else:
            parts.append(
                f"REVIEW was selected because only {len(strong_categories)} distinct "
                f"strong category/categories were present; a HIGH finding alone does "
                "not meet the requirement for at least two independent strong categories."
            )

    if ai_status in {"unavailable", "invalid"}:
        parts.append(
            f"Stage 2 was {ai_status} and was excluded; it cannot change deterministic evidence."
        )
    elif ai_status == "complete":
        parts.append("Validated Stage 2 output is contextual only and cannot change the band.")
    if uncertainty_reasons:
        parts.append("Uncertainty and incomplete-check notes: " + "; ".join(uncertainty_reasons))
    return " ".join(parts)


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

    rationale_uncertainty_reasons = uncertainty_reasons(
        result, validated.ai_analysis, ai_status=validated.ai_status
    )
    rationale = _decision_rationale(
        result,
        validated.findings,
        final_band=final_band,
        policy_rules=policy_rules,
        ai_status=validated.ai_status,
        uncertainty_reasons=rationale_uncertainty_reasons,
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
        uncertainty_reasons=rationale_uncertainty_reasons,
        recommendations=recommendations,
    )
