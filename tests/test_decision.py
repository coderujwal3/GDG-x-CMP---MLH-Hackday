from __future__ import annotations

import pytest

from scamsentry.ai.schemas import AIAnalysis, parse_ai_response
from scamsentry.analyzer import analyse_message
from scamsentry.decision import assess
from scamsentry.decision.validation import DecisionInputError
from scamsentry.models import (
    AnalysisStatus,
    Category,
    EvidenceSource,
    Finding,
    FindingSource,
    ObservationKind,
    RiskBand,
    Severity,
)


def _finding(
    finding_id: str,
    category: Category,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=f"TEST_{category.value.upper()}",
        category=category,
        severity=severity,
        title=f"{category.value} indicator",
        evidence_text="verify immediately",
        evidence_source=EvidenceSource.ORIGINAL,
        explanation=f"A {category.value} indicator was observed.",
        observation_kind=ObservationKind.HEURISTIC,
        source=FindingSource.DETERMINISTIC,
        start_offset=0,
        end_offset=5,
    )


def _stage1(*findings: Finding, band: RiskBand | None = None):
    result = analyse_message("verify immediately")
    result.findings = list(findings)
    result.risk_band = band
    return result


def _ai(
    intent: str = "benign_or_informational",
    finding_ids: list[str] | None = None,
    uncertainty: str = "moderate",
) -> AIAnalysis:
    import json

    raw = {
        "summary": "The message could be an ordinary notice.",
        "likely_intent": intent,
        "tactics": ["none_observed"],
        "finding_explanations": [
            {"finding_id": finding_id, "interpretation": "This indicator has context."}
            for finding_id in finding_ids or []
        ],
        "uncertainty": uncertainty,
        "uncertainty_reasons": (
            [] if uncertainty == "low" else ["The sender is unknown."]
        ),
        "alternative_explanations": ["It may be a routine notification."],
        "recommended_actions": ["Verify using a known channel."],
    }
    return parse_ai_response(
        json.dumps(raw),
        valid_finding_ids=set(finding_ids or []),
        model_id="test-model",
    )


def test_empty_findings_are_inconclusive_not_low_concern() -> None:
    decision = assess(_stage1(band=RiskBand.LOW_CONCERN))
    payload = decision.to_dict()
    assert payload["final_risk_band"] == "INCONCLUSIVE"
    assert payload["stage1_risk_band"] == "LOW_CONCERN"
    assert payload["heuristic_score"] is None
    assert payload["uncertainty"] == "high"
    assert payload["recommendations"][0]["action_id"] == "verify_independently"
    assert payload["supporting_finding_ids"] == []


def test_recomputes_correlated_urgency_and_impersonation_without_double_counting() -> None:
    result = _stage1(
        _finding("F001", Category.URGENCY),
        _finding("F002", Category.IMPERSONATION),
        band=RiskBand.HIGH_CONCERN,
    )
    decision = assess(result)
    assert decision.final_risk_band is RiskBand.REVIEW
    assert "correlated_urgency_impersonation_not_double_counted" in decision.policy_rules
    assert "stage 1 risk band did not match" in decision.notes[0].lower()


def test_independent_high_categories_produce_high_and_linked_actions() -> None:
    result = _stage1(
        _finding("F001", Category.CREDENTIAL),
        _finding("F002", Category.URL),
        band=RiskBand.HIGH_CONCERN,
    )
    decision = assess(result)
    payload = decision.to_dict()
    assert decision.final_risk_band is RiskBand.HIGH_CONCERN
    assert payload["supporting_finding_ids"] == ["F001", "F002"]
    recommendation_map = {
        item["action_id"]: item for item in payload["recommendations"]
    }
    assert recommendation_map["protect_credentials"]["supporting_finding_ids"] == ["F001"]
    assert recommendation_map["avoid_suspicious_link"]["supporting_finding_ids"] == ["F002"]
    assert all(item["priority"] == "immediate" for item in payload["recommendations"])


@pytest.mark.parametrize(
    "category",
    [Category.URL, Category.CREDENTIAL, Category.PAYMENT],
)
def test_one_high_finding_remains_review_under_documented_policy(
    category: Category,
) -> None:
    result = _stage1(_finding("F001", category), band=RiskBand.REVIEW)
    decision = assess(result)
    payload = decision.to_dict()

    assert decision.final_risk_band is RiskBand.REVIEW
    assert payload["risk_policy_version"] == "1.0"
    assert "Stage 1 risk band: REVIEW" in decision.rationale
    assert "Stage 3 final risk band: REVIEW" in decision.rationale
    assert "F001" in decision.rationale
    assert "HIGH finding alone does not meet" in decision.rationale
    assert "stage1_high_threshold_not_met" in decision.policy_rules


def test_stage2_is_context_only_and_conflict_is_reported() -> None:
    result = _stage1(_finding("F001", Category.PAYMENT), band=RiskBand.REVIEW)
    before = result.to_dict()
    ai = _ai(finding_ids=["F001"])
    decision = assess(result, ai)
    assert decision.final_risk_band is RiskBand.REVIEW
    assert decision.ai_status == "complete"
    assert any("conflicts with Stage 1" in note for note in decision.notes)
    assert all(
        signal.reference_id is None or signal.reference_id == "F001"
        for signal in decision.signals
    )
    assert result.to_dict() == before
    assert ai.to_dict()["status"] == "complete"


def test_suspicious_ai_without_stage1_findings_does_not_raise_band() -> None:
    decision = assess(
        _stage1(band=RiskBand.LOW_CONCERN),
        _ai(intent="obtain_credentials"),
    )
    assert decision.final_risk_band is RiskBand.INCONCLUSIVE
    assert any("did not raise the risk band" in note for note in decision.notes)


def test_low_model_uncertainty_cannot_lower_decision_uncertainty() -> None:
    result = _stage1(_finding("F001", Category.CREDENTIAL), band=RiskBand.REVIEW)
    decision = assess(result, _ai(uncertainty="low"))
    assert decision.uncertainty.value == "moderate"
    assert any(
        "not externally verified" in reason
        for reason in decision.to_dict()["uncertainty_reasons"]
    )


def test_unavailable_or_invalid_ai_does_not_block_stage1_decision() -> None:
    finding = _finding("F001", Category.CREDENTIAL)
    result = _stage1(finding, band=RiskBand.REVIEW)
    unavailable = assess(result, ai_status="unavailable")
    malformed = assess(result, {"status": "incomplete"})
    assert unavailable.final_risk_band is RiskBand.REVIEW
    assert unavailable.ai_status == "unavailable"
    assert malformed.final_risk_band is RiskBand.REVIEW
    assert malformed.ai_status == "invalid"
    assert not any(signal.source.value == "stage2" for signal in malformed.signals)
    assert any("invalid" in reason for reason in malformed.to_dict()["uncertainty_reasons"])
    assert "Stage 2 was invalid and was excluded" in malformed.rationale


def test_incomplete_stage1_is_inconclusive_and_uncertain() -> None:
    result = _stage1(_finding("F001", Category.CREDENTIAL), band=RiskBand.HIGH_CONCERN)
    result.analysis_status = AnalysisStatus.PARTIAL
    decision = assess(result)
    assert decision.final_risk_band is RiskBand.INCONCLUSIVE
    assert decision.uncertainty.value == "unable_to_assess"
    assert "Stage 1 status is partial" in decision.rationale
    assert "dns_resolution" in decision.rationale
    assert any(
        "Stage 1 checks were not performed: dns_resolution" in reason
        for reason in decision.uncertainty_reasons
    )


def test_malformed_stage1_is_rejected() -> None:
    result = _stage1(_finding("F001", Category.CREDENTIAL))
    result.findings.append(_finding("F001", Category.URL))
    with pytest.raises(DecisionInputError, match="unique"):
        assess(result)


def test_unsupported_stage1_schema_is_rejected() -> None:
    result = _stage1(_finding("F001", Category.CREDENTIAL))
    result.schema_version = "9.0"
    with pytest.raises(DecisionInputError, match="schema version"):
        assess(result)


def test_results_are_deterministic_and_preserve_stage1_values() -> None:
    result = _stage1(
        _finding("F001", Category.CREDENTIAL),
        _finding("F002", Category.URL),
        band=RiskBand.HIGH_CONCERN,
    )
    before = result.to_dict()
    first = assess(result).to_dict()
    second = assess(result).to_dict()
    assert first == second
    assert result.to_dict() == before
    assert "HIGH_CONCERN was selected because 2 distinct strong categories" in first["rationale"]
    assert "HIGH_CONCERN" in first["rationale"]
