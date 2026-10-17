"""Strict, dependency-free validation and typed AI-analysis results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from scamsentry.ai.ollama_provider import MAX_MODEL_OUTPUT_BYTES
from scamsentry.ai.provider import AIAnalysisError, AIErrorCode

AI_SCHEMA_VERSION = "1.0"
AI_ADVISORY = (
    "Advisory model interpretation only; it is not proof of maliciousness, "
    "a calibrated probability, or a replacement for Stage 1 evidence."
)
MAX_SUMMARY_LENGTH = 800
MAX_TEXT_LENGTH = 500
MAX_MODEL_ID_LENGTH = 128
MAX_TACTICS = 8
MAX_FINDING_EXPLANATIONS = 64
MAX_LIST_ITEMS = 8


class LikelyIntent(str, Enum):
    OBTAIN_CREDENTIALS = "obtain_credentials"
    OBTAIN_PAYMENT = "obtain_payment"
    INDUCE_LINK_VISIT = "induce_link_visit"
    COLLECT_PERSONAL_INFORMATION = "collect_personal_information"
    CREATE_FEAR_OR_URGENCY = "create_fear_or_urgency"
    IMPERSONATE_AN_ORGANISATION = "impersonate_an_organisation"
    UNSOLICITED_MARKETING = "unsolicited_marketing"
    BENIGN_OR_INFORMATIONAL = "benign_or_informational"
    UNCLEAR = "unclear"


class Tactic(str, Enum):
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    URGENCY_OR_TIME_PRESSURE = "urgency_or_time_pressure"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    PAYMENT_OR_FEE_PRESSURE = "payment_or_fee_pressure"
    PRIZE_OR_REWARD_LURE = "prize_or_reward_lure"
    FEAR_OR_THREAT = "fear_or_threat"
    SOCIAL_PROOF = "social_proof"
    ROMANCE_OR_TRUST_EXPLOITATION = "romance_or_trust_exploitation"
    DELIVERY_OR_ACCOUNT_LURE = "delivery_or_account_lure"
    MALICIOUS_LINK_LURE = "malicious_link_lure"
    OTHER = "other"
    NONE_OBSERVED = "none_observed"


class Uncertainty(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    UNABLE_TO_ASSESS = "unable_to_assess"


@dataclass(frozen=True)
class FindingExplanation:
    finding_id: str
    interpretation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class AIAnalysis:
    """Validated model interpretation kept distinct from the Stage 1 result."""

    summary: str
    likely_intent: LikelyIntent
    tactics: tuple[Tactic, ...]
    finding_explanations: tuple[FindingExplanation, ...]
    uncertainty: Uncertainty
    uncertainty_reasons: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    model: str
    schema_version: str = AI_SCHEMA_VERSION
    advisory: str = AI_ADVISORY
    status: str = "complete"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "schema_version": self.schema_version,
            "model": self.model,
            "advisory": self.advisory,
            "summary": self.summary,
            "likely_intent": self.likely_intent.value,
            "tactics": [item.value for item in self.tactics],
            "finding_explanations": [
                item.to_dict() for item in self.finding_explanations
            ],
            "uncertainty": self.uncertainty.value,
            "uncertainty_reasons": list(self.uncertainty_reasons),
            "alternative_explanations": list(self.alternative_explanations),
            "recommended_actions": list(self.recommended_actions),
        }


_RESPONSE_FIELDS = frozenset(
    {
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


def _required_text(value: Any, field: str, *, limit: int) -> str:
    if not isinstance(value, str):
        raise AIAnalysisError(
            f"Field {field!r} must be a string.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if not value.strip():
        raise AIAnalysisError(
            f"Field {field!r} must not be empty.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if len(value) > limit:
        raise AIAnalysisError(
            f"Field {field!r} exceeds the {limit}-character limit.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    return value.strip()


def _text_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AIAnalysisError(
            f"Field {field!r} must be an array of strings.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    if not value or len(value) > MAX_LIST_ITEMS:
        raise AIAnalysisError(
            f"Field {field!r} must contain between 1 and {MAX_LIST_ITEMS} items.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    items = tuple(
        _required_text(item, f"{field}[{index}]", limit=MAX_TEXT_LENGTH)
        for index, item in enumerate(value)
    )
    if len(set(items)) != len(items):
        raise AIAnalysisError(
            f"Field {field!r} must not contain duplicates.",
            code=AIErrorCode.INVALID_SCHEMA,
        )
    return items


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def parse_ai_response(
    raw_output: str,
    *,
    valid_finding_ids: set[str],
    model_id: str,
) -> AIAnalysis:
    """Parse and validate one model JSON object against the controlled schema."""

    if not isinstance(raw_output, str):
        raise AIAnalysisError(
            "Model output must be text.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    if len(raw_output.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
        raise AIAnalysisError(
            f"Model output exceeded the {MAX_MODEL_OUTPUT_BYTES}-byte limit.",
            code=AIErrorCode.OUTPUT_TOO_LARGE,
            model_id=model_id,
        )
    try:
        payload = json.loads(raw_output, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise AIAnalysisError(
            "Model output is not valid JSON.",
            code=AIErrorCode.INVALID_JSON,
            model_id=model_id,
        ) from exc
    except ValueError as exc:
        raise AIAnalysisError(
            "Model output contains duplicate JSON object keys.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        ) from exc
    if not isinstance(payload, dict):
        raise AIAnalysisError(
            "Model output root must be a JSON object.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    missing = _RESPONSE_FIELDS - payload.keys()
    extra = payload.keys() - _RESPONSE_FIELDS
    if missing:
        raise AIAnalysisError(
            "Model output is missing one or more required fields.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    if extra:
        raise AIAnalysisError(
            "Model output contains unexpected fields.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )

    summary = _required_text(
        payload["summary"], "summary", limit=MAX_SUMMARY_LENGTH
    )
    try:
        intent = LikelyIntent(payload["likely_intent"])
    except (ValueError, TypeError) as exc:
        raise AIAnalysisError(
            "Field 'likely_intent' is not a supported label.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        ) from exc

    raw_tactics = payload["tactics"]
    if not isinstance(raw_tactics, list) or not 1 <= len(raw_tactics) <= MAX_TACTICS:
        raise AIAnalysisError(
            f"Field 'tactics' must contain between 1 and {MAX_TACTICS} labels.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    try:
        tactics = tuple(Tactic(item) for item in raw_tactics)
    except (ValueError, TypeError) as exc:
        raise AIAnalysisError(
            "Field 'tactics' contains an unsupported label.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        ) from exc
    if len(set(tactics)) != len(tactics):
        raise AIAnalysisError(
            "Field 'tactics' must not contain duplicate labels.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    if Tactic.NONE_OBSERVED in tactics and len(tactics) > 1:
        raise AIAnalysisError(
            "'none_observed' cannot be combined with another tactic.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )

    raw_explanations = payload["finding_explanations"]
    if (
        not isinstance(raw_explanations, list)
        or len(raw_explanations) > MAX_FINDING_EXPLANATIONS
    ):
        raise AIAnalysisError(
            f"Field 'finding_explanations' must contain at most "
            f"{MAX_FINDING_EXPLANATIONS} items.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    explanations: list[FindingExplanation] = []
    explained_ids: set[str] = set()
    for index, item in enumerate(raw_explanations):
        if not isinstance(item, dict) or item.keys() != {"finding_id", "interpretation"}:
            raise AIAnalysisError(
                f"Finding explanation {index} must contain only finding_id and interpretation.",
                code=AIErrorCode.INVALID_SCHEMA,
                model_id=model_id,
            )
        finding_id = _required_text(
            item["finding_id"], f"finding_explanations[{index}].finding_id", limit=64
        )
        if finding_id not in valid_finding_ids:
            raise AIAnalysisError(
                "Finding explanation references an unknown Stage 1 ID.",
                code=AIErrorCode.INVALID_SCHEMA,
                model_id=model_id,
            )
        if finding_id in explained_ids:
            raise AIAnalysisError(
                "A Stage 1 finding ID is explained more than once.",
                code=AIErrorCode.INVALID_SCHEMA,
                model_id=model_id,
            )
        explained_ids.add(finding_id)
        interpretation = _required_text(
            item["interpretation"],
            f"finding_explanations[{index}].interpretation",
            limit=MAX_TEXT_LENGTH,
        )
        explanations.append(FindingExplanation(finding_id, interpretation))

    try:
        uncertainty = Uncertainty(payload["uncertainty"])
    except (ValueError, TypeError) as exc:
        raise AIAnalysisError(
            "Field 'uncertainty' is not a supported label.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        ) from exc
    reasons_value = payload["uncertainty_reasons"]
    if not isinstance(reasons_value, list):
        raise AIAnalysisError(
            "Field 'uncertainty_reasons' must be an array of strings.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    if uncertainty in {Uncertainty.HIGH, Uncertainty.UNABLE_TO_ASSESS} and not reasons_value:
        raise AIAnalysisError(
            "High or unable_to_assess uncertainty requires at least one reason.",
            code=AIErrorCode.INVALID_SCHEMA,
            model_id=model_id,
        )
    if reasons_value:
        reasons = _text_list(reasons_value, "uncertainty_reasons")
    else:
        reasons = ()

    alternatives = _text_list(
        payload["alternative_explanations"], "alternative_explanations"
    )
    actions = _text_list(payload["recommended_actions"], "recommended_actions")
    model = _required_text(model_id, "model", limit=MAX_MODEL_ID_LENGTH)
    return AIAnalysis(
        summary=summary,
        likely_intent=intent,
        tactics=tactics,
        finding_explanations=tuple(explanations),
        uncertainty=uncertainty,
        uncertainty_reasons=reasons,
        alternative_explanations=alternatives,
        recommended_actions=actions,
        model=model,
    )
