"""Validation of Stage 1 evidence and optional Stage 2 interpretations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from scamsentry.ai.provider import AIAnalysisError, AIErrorCode
from scamsentry.ai.schemas import AI_ADVISORY, AI_SCHEMA_VERSION, AIAnalysis, parse_ai_response
from scamsentry.models import (
    AnalysisResult,
    AnalysisStatus,
    Category,
    EvidenceSource,
    Finding,
    FindingSource,
    ObservationKind,
    RiskBand,
    Severity,
)
from scamsentry.normalizer import utf8_byte_length

_FINDING_ID = re.compile(r"^F[0-9]{3,}$")
_ALLOWED_AI_STATUSES = frozenset(
    {"not_requested", "complete", "unavailable", "invalid"}
)
_AI_FIELDS = frozenset(
    {
        "status",
        "schema_version",
        "model",
        "advisory",
        "summary",
        "likely_intent",
        "tactics",
        "finding_explanations",
        "uncertainty",
        "uncertainty_reasons",
        "alternative_explanations",
        "recommended_actions",
    }
)


class DecisionInputError(ValueError):
    """Malformed Stage 1 structure or unsupported decision input configuration."""


@dataclass(frozen=True)
class ValidatedInputs:
    findings: tuple[Finding, ...]
    ai_analysis: AIAnalysis | None
    ai_status: str


def validate_stage1(result: AnalysisResult) -> tuple[Finding, ...]:
    """Validate the Stage 1 typed object before using it for a final decision."""

    if not isinstance(result, AnalysisResult):
        raise DecisionInputError("Stage 1 input must be an AnalysisResult.")
    if result.schema_version != "1.0":
        raise DecisionInputError("Unsupported Stage 1 schema version.")
    if not isinstance(result.original_message, str) or not result.original_message.strip():
        raise DecisionInputError("Stage 1 original message is invalid or empty.")
    if not isinstance(result.normalised_message, str):
        raise DecisionInputError("Stage 1 normalized message is invalid or oversized.")
    try:
        original_size = utf8_byte_length(result.original_message)
        normalized_size = utf8_byte_length(result.normalised_message)
    except UnicodeEncodeError as exc:
        raise DecisionInputError("Stage 1 message contains invalid Unicode.") from exc
    if original_size > 50 * 1024:
        raise DecisionInputError("Stage 1 original message is invalid or oversized.")
    if normalized_size > 50 * 1024:
        raise DecisionInputError("Stage 1 normalized message is invalid or oversized.")
    if not isinstance(result.analysis_status, AnalysisStatus):
        raise DecisionInputError("Stage 1 analysis status is invalid.")
    if result.risk_band is not None and not isinstance(result.risk_band, RiskBand):
        raise DecisionInputError("Stage 1 risk band is invalid.")
    for name, values, limit in (
        ("checks_performed", result.checks_performed, 32),
        ("limitations", result.limitations, 32),
        ("notes", result.notes, 32),
    ):
        if not isinstance(values, tuple) or len(values) > limit:
            raise DecisionInputError(f"Stage 1 {name} list is invalid.")
        if any(not isinstance(item, str) or not item or len(item) > 500 for item in values):
            raise DecisionInputError(f"Stage 1 {name} entry is invalid.")
    if not isinstance(result.risk_policy, str) or len(result.risk_policy) > 2_000:
        raise DecisionInputError("Stage 1 risk policy description is invalid.")
    if not isinstance(result.findings, list) or len(result.findings) > 128:
        raise DecisionInputError("Stage 1 findings must be a list of at most 128 items.")
    if not isinstance(result.checks_incomplete, tuple) or len(result.checks_incomplete) > 32:
        raise DecisionInputError("Stage 1 incomplete-check list is invalid.")
    for check in result.checks_incomplete:
        if not isinstance(check, str) or not check or len(check) > 100:
            raise DecisionInputError("Stage 1 incomplete-check entry is invalid.")

    seen: set[str] = set()
    for finding in result.findings:
        if not isinstance(finding, Finding):
            raise DecisionInputError("Stage 1 contains a malformed finding.")
        if (
            not isinstance(finding.id, str)
            or _FINDING_ID.fullmatch(finding.id) is None
            or finding.id in seen
        ):
            raise DecisionInputError("Stage 1 finding IDs must be valid and unique.")
        seen.add(finding.id)
        if not isinstance(finding.rule_id, str) or not finding.rule_id or len(finding.rule_id) > 100:
            raise DecisionInputError(f"Stage 1 finding {finding.id} has an invalid rule ID.")
        if not isinstance(finding.category, Category):
            raise DecisionInputError(f"Stage 1 finding {finding.id} has an invalid category.")
        if not isinstance(finding.severity, Severity):
            raise DecisionInputError(f"Stage 1 finding {finding.id} has an invalid severity.")
        if not isinstance(finding.evidence_source, EvidenceSource):
            raise DecisionInputError(f"Stage 1 finding {finding.id} has an invalid evidence source.")
        if not isinstance(finding.observation_kind, ObservationKind):
            raise DecisionInputError(f"Stage 1 finding {finding.id} has an invalid observation kind.")
        if finding.source is not FindingSource.DETERMINISTIC:
            raise DecisionInputError("Stage 1 evidence must have deterministic provenance.")
        for name, value, limit in (
            ("title", finding.title, 300),
            ("evidence_text", finding.evidence_text, 2_000),
            ("explanation", finding.explanation, 1_000),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > limit:
                raise DecisionInputError(
                    f"Stage 1 finding {finding.id} has invalid {name}."
                )
        if (finding.start_offset is None) != (finding.end_offset is None):
            raise DecisionInputError(f"Stage 1 finding {finding.id} has invalid offsets.")
        if finding.start_offset is not None:
            if (
                isinstance(finding.start_offset, bool)
                or isinstance(finding.end_offset, bool)
                or not isinstance(finding.start_offset, int)
                or not isinstance(finding.end_offset, int)
                or finding.start_offset < 0
                or finding.end_offset < finding.start_offset
                or finding.end_offset > len(result.original_message)
            ):
                raise DecisionInputError(f"Stage 1 finding {finding.id} has invalid offsets.")
    return tuple(result.findings)


def _validate_ai_payload(
    value: AIAnalysis | dict[str, Any],
    *,
    valid_finding_ids: set[str],
) -> AIAnalysis:
    if isinstance(value, AIAnalysis):
        payload = value.to_dict()
    elif isinstance(value, dict):
        payload = value
    else:
        raise AIAnalysisError(
            "Stage 2 result must be a validated AIAnalysis object or object mapping.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if payload.keys() != _AI_FIELDS:
        raise AIAnalysisError(
            "Stage 2 result has missing or unexpected envelope fields.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if payload["status"] != "complete" or payload["schema_version"] != AI_SCHEMA_VERSION:
        raise AIAnalysisError(
            "Stage 2 status or schema version is unsupported.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    model = payload["model"]
    if not isinstance(model, str) or not model.strip() or len(model) > 128:
        raise AIAnalysisError(
            "Stage 2 model identifier is invalid.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if payload["advisory"] != AI_ADVISORY:
        raise AIAnalysisError(
            "Stage 2 advisory disclaimer is invalid.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    model_fields = {
        key: payload[key]
        for key in _AI_FIELDS
        if key not in {"status", "schema_version", "model", "advisory"}
    }
    return parse_ai_response(
        json.dumps(model_fields, ensure_ascii=False),
        valid_finding_ids=valid_finding_ids,
        model_id=model,
    )


def validate_inputs(
    result: AnalysisResult,
    ai_analysis: AIAnalysis | dict[str, Any] | None,
    *,
    ai_status: str | None = None,
) -> ValidatedInputs:
    findings = validate_stage1(result)
    if ai_status is not None and ai_status not in _ALLOWED_AI_STATUSES:
        raise DecisionInputError("Unsupported AI availability status.")
    if ai_analysis is None:
        status = ai_status or "not_requested"
        return ValidatedInputs(findings, None, status)
    try:
        parsed = _validate_ai_payload(
            ai_analysis,
            valid_finding_ids={finding.id for finding in findings},
        )
        if ai_status not in (None, "complete"):
            raise AIAnalysisError(
                "AI status conflicts with the supplied Stage 2 result.",
                code=AIErrorCode.INVALID_SCHEMA,
            )
    except (AIAnalysisError, AttributeError, TypeError, ValueError, KeyError):
        return ValidatedInputs(findings, None, "invalid")
    return ValidatedInputs(findings, parsed, "complete")
