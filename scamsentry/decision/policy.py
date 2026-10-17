"""Versioned deterministic policy for final risk and user recommendations."""

from __future__ import annotations

from collections.abc import Iterable

from scamsentry.analyzer import assign_risk_band
from scamsentry.ai.schemas import AIAnalysis, Uncertainty
from scamsentry.decision.models import (
    DecisionSignal,
    Recommendation,
    RecommendationPriority,
    SignalSource,
)
from scamsentry.models import (
    AnalysisResult,
    AnalysisStatus,
    Category,
    Finding,
    RiskBand,
    Severity,
)


def assess_risk(
    result: AnalysisResult,
    findings: tuple[Finding, ...],
) -> tuple[RiskBand, tuple[str, ...], tuple[str, ...]]:
    """Return a conservative Stage 3 band, rule trace, and policy notes."""

    notes: list[str] = []
    if result.analysis_status is not AnalysisStatus.COMPLETE:
        return (
            RiskBand.INCONCLUSIVE,
            ("stage1_incomplete",),
            ("Stage 1 analysis was incomplete; the final assessment is inconclusive.",),
        )
    if not findings:
        notes.append(
            "No Stage 1 indicators were found; absence of findings does not establish safety."
        )
        if result.risk_band is not RiskBand.LOW_CONCERN:
            notes.append("Stage 1 risk band differed from its no-findings policy expectation.")
        return RiskBand.INCONCLUSIVE, ("no_findings_inconclusive",), tuple(notes)

    computed = assign_risk_band(list(findings), result.analysis_status)
    if result.risk_band is not computed:
        notes.append(
            "The supplied Stage 1 risk band did not match its findings; Stage 3 recomputed "
            "the Stage 1 policy result from validated findings."
        )
    rules_list = ["stage1_findings_present"]
    strong_categories = {
        finding.category
        for finding in findings
        if finding.severity in {Severity.MEDIUM, Severity.HIGH}
    }
    if strong_categories == {Category.URGENCY, Category.IMPERSONATION}:
        rules_list.append("correlated_urgency_impersonation_not_double_counted")
    if computed is RiskBand.HIGH_CONCERN:
        rules_list.extend(
            ("stage1_independent_strong_categories", "stage1_at_least_one_high_severity")
        )
    else:
        rules_list.append("stage1_high_threshold_not_met")
    rules = tuple(rules_list)
    return computed, rules, tuple(notes)


def build_signals(
    findings: tuple[Finding, ...],
    ai_analysis: AIAnalysis | None,
) -> tuple[DecisionSignal, ...]:
    signals: list[DecisionSignal] = []
    for finding in findings:
        signals.append(
            DecisionSignal(
                signal_id=f"stage1:{finding.id}",
                source=SignalSource.STAGE1,
                category=finding.category.value,
                reference_id=finding.id,
                severity=finding.severity.value,
                explanation=finding.explanation,
            )
        )
    if ai_analysis is not None:
        signals.append(
            DecisionSignal(
                signal_id="stage2:intent",
                source=SignalSource.STAGE2,
                category="likely_intent",
                reference_id=None,
                severity=None,
                explanation=ai_analysis.likely_intent.value,
            )
        )
        signals.extend(
            DecisionSignal(
                signal_id=f"stage2:tactic:{index:02d}",
                source=SignalSource.STAGE2,
                category="tactic",
                reference_id=None,
                severity=None,
                explanation=tactic.value,
            )
            for index, tactic in enumerate(ai_analysis.tactics, start=1)
        )
    return tuple(signals)


def build_recommendations(
    risk_band: RiskBand,
    findings: tuple[Finding, ...],
) -> tuple[Recommendation, ...]:
    by_category: dict[Category, list[Finding]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    priority = (
        RecommendationPriority.IMMEDIATE
        if risk_band is RiskBand.HIGH_CONCERN
        else RecommendationPriority.SOON
        if risk_band is RiskBand.REVIEW
        else RecommendationPriority.ROUTINE
    )
    recommendations: list[Recommendation] = []

    def add(
        action_id: str,
        action: str,
        reason: str,
        categories: Iterable[Category],
        *,
        fallback: bool = False,
    ) -> None:
        ids = tuple(
            finding.id
            for category in categories
            for finding in by_category.get(category, ())
        )
        if ids or fallback:
            recommendations.append(
                Recommendation(
                    action_id=action_id,
                    action=action,
                    reason=reason,
                    supporting_finding_ids=ids,
                    priority=priority,
                )
            )

    add(
        "verify_independently",
        "Pause and verify the request through a contact method or website you already trust.",
        "Independent verification is prudent for suspicious or unverified messages.",
        tuple(Category),
        fallback=True,
    )
    add(
        "protect_credentials",
        "Do not enter passwords or one-time codes through links in this message.",
        "Stage 1 found a credential-related indicator.",
        (Category.CREDENTIAL,),
    )
    add(
        "avoid_payment",
        "Do not send money, gift cards, or cryptocurrency based on this message.",
        "Stage 1 found a payment-related indicator.",
        (Category.PAYMENT,),
    )
    add(
        "avoid_suspicious_link",
        "Avoid opening the embedded link; navigate to the official service independently.",
        "Stage 1 found a URL-structure indicator; the destination was not fetched or verified.",
        (Category.URL,),
    )
    add(
        "resist_pressure",
        "Do not let urgency or claimed authority rush a decision; verify through an official channel.",
        "Stage 1 found urgency or impersonation indicators.",
        (Category.URGENCY, Category.IMPERSONATION),
    )
    add(
        "inspect_unusual_formatting",
        "Treat unusual or invisible formatting as untrusted and compare the message in a plain-text view.",
        "Stage 1 found a formatting indicator.",
        (Category.FORMATTING,),
    )
    return tuple(recommendations)


def confidence_uncertainty(
    result: AnalysisResult,
    ai_analysis: AIAnalysis | None,
    *,
    ai_status: str,
) -> Uncertainty:
    if result.analysis_status is not AnalysisStatus.COMPLETE:
        return Uncertainty.UNABLE_TO_ASSESS
    if not result.findings:
        return Uncertainty.HIGH
    if ai_analysis is not None:
        uncertainty_order = {
            Uncertainty.LOW: 0,
            Uncertainty.MODERATE: 1,
            Uncertainty.HIGH: 2,
            Uncertainty.UNABLE_TO_ASSESS: 3,
        }
        stage1_floor = Uncertainty.MODERATE
        return max(
            (stage1_floor, ai_analysis.uncertainty),
            key=uncertainty_order.__getitem__,
        )
    if ai_status in {"unavailable", "invalid"}:
        return Uncertainty.HIGH
    return Uncertainty.MODERATE


def uncertainty_reasons(
    result: AnalysisResult,
    ai_analysis: AIAnalysis | None,
    *,
    ai_status: str,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if result.analysis_status is not AnalysisStatus.COMPLETE:
        reasons.append(
            f"Stage 1 status is {result.analysis_status.value}; the analysis is incomplete."
        )
    elif not result.findings:
        reasons.append(
            "No implemented Stage 1 checks fired; absence of findings does not establish safety."
        )
    else:
        reasons.append(
            "Sender identity and destination reputation were not externally verified."
        )
    if result.checks_incomplete:
        reasons.append(
            "Stage 1 checks were not performed: " + ", ".join(result.checks_incomplete) + "."
        )
    if ai_analysis is not None:
        reasons.extend(ai_analysis.uncertainty_reasons)
    elif ai_status == "unavailable":
        reasons.append("Optional Stage 2 interpretation was unavailable.")
    elif ai_status == "invalid":
        reasons.append("Optional Stage 2 output was invalid and excluded.")
    return tuple(dict.fromkeys(reasons))
