"""Dependency-free validation for untrusted model output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


TACTICS = frozenset({
    "authority_impersonation",
    "urgency_or_time_pressure",
    "credential_harvesting",
    "payment_or_fee_pressure",
    "prize_or_reward_lure",
    "fear_or_threat",
    "social_proof",
    "romance_or_trust_exploitation",
    "delivery_or_account_lure",
    "malicious_link_lure",
    "other",
    "none_observed",
})
INTENTS = frozenset({
    "obtain_credentials",
    "obtain_payment",
    "induce_link_visit",
    "collect_personal_information",
    "create_fear_or_urgency",
    "impersonate_an_organisation",
    "unsolicited_marketing",
    "benign_or_informational",
    "unclear",
})
UNCERTAINTY = frozenset({"low", "moderate", "high", "unable_to_assess"})


class AIOutputValidationError(ValueError):
    """The model response did not match the required safe output schema."""


@dataclass(frozen=True)
class AIAnalysis:
    summary: str
    likely_intent: str
    tactics: tuple[str, ...]
    finding_explanations: tuple[dict[str, str], ...]
    uncertainty: str
    uncertainty_reasons: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    limitations: tuple[str, ...]
    model: str
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": "complete",
            "model": self.model,
            "summary": self.summary,
            "likely_intent": self.likely_intent,
            "tactics": list(self.tactics),
            "finding_explanations": list(self.finding_explanations),
            "uncertainty": self.uncertainty,
            "uncertainty_reasons": list(self.uncertainty_reasons),
            "alternative_explanations": list(self.alternative_explanations),
            "recommended_actions": list(self.recommended_actions),
            "limitations": list(self.limitations),
            "disclaimer": (
                "AI interpretation is advisory, may be wrong, and is not proof "
                "that a message or destination is malicious."
            ),
        }


def _text(value: Any, field: str, *, maximum: int = 1200) -> str:
    if not isinstance(value, str):
        raise AIOutputValidationError(f"{field} must be a string")
    value = value.strip()
    if not value or len(value) > maximum:
        raise AIOutputValidationError(f"{field} must contain 1-{maximum} characters")
    return value


def _string_list(value: Any, field: str, *, limit: int = 8) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > limit:
        raise AIOutputValidationError(f"{field} must be a list with at most {limit} items")
    items = tuple(_text(item, field, maximum=500) for item in value)
    return items


def parse_ai_output(raw: str, *, model: str, finding_ids: set[str]) -> AIAnalysis:
    """Parse and strictly validate JSON from an untrusted model response."""
    if not isinstance(raw, str) or len(raw) > 20000:
        raise AIOutputValidationError("Model output is missing or exceeds 20000 characters")
    candidate = raw.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            candidate = "\n".join(lines[1:-1]).strip()
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise AIOutputValidationError("Model output is not valid JSON") from exc
    if not isinstance(data, dict):
        raise AIOutputValidationError("Model output must be a JSON object")

    required = {
        "summary", "likely_intent", "tactics", "finding_explanations",
        "uncertainty", "uncertainty_reasons", "alternative_explanations",
        "recommended_actions",
    }
    if set(data) != required:
        missing = sorted(required - set(data))
        extra = sorted(set(data) - required)
        raise AIOutputValidationError(f"Incorrect fields; missing={missing}, extra={extra}")

    intent = data["likely_intent"]
    if intent not in INTENTS:
        raise AIOutputValidationError("Unknown likely_intent")
    uncertainty = data["uncertainty"]
    if uncertainty not in UNCERTAINTY:
        raise AIOutputValidationError("Unknown uncertainty level")
    tactics = _string_list(data["tactics"], "tactics", limit=8)
    if any(item not in TACTICS for item in tactics):
        raise AIOutputValidationError("Unknown tactic label")
    if not tactics:
        raise AIOutputValidationError("tactics must contain at least one label")

    raw_explanations = data["finding_explanations"]
    if not isinstance(raw_explanations, list) or len(raw_explanations) > 50:
        raise AIOutputValidationError("finding_explanations must be a list of at most 50 items")
    explanations: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_explanations:
        if not isinstance(item, dict) or set(item) != {"finding_id", "interpretation"}:
            raise AIOutputValidationError("Each finding explanation needs finding_id and interpretation")
        finding_id = _text(item["finding_id"], "finding_id", maximum=20)
        if finding_id not in finding_ids:
            raise AIOutputValidationError(f"Unknown finding_id: {finding_id}")
        if finding_id in seen:
            raise AIOutputValidationError(f"Duplicate finding_id: {finding_id}")
        seen.add(finding_id)
        explanations.append({
            "finding_id": finding_id,
            "interpretation": _text(item["interpretation"], "interpretation", maximum=700),
        })

    reasons = _string_list(data["uncertainty_reasons"], "uncertainty_reasons")
    alternatives = _string_list(data["alternative_explanations"], "alternative_explanations")
    actions = _string_list(data["recommended_actions"], "recommended_actions")
    if uncertainty in {"high", "unable_to_assess"} and not reasons:
        raise AIOutputValidationError("High or unassessable uncertainty requires reasons")

    return AIAnalysis(
        summary=_text(data["summary"], "summary"),
        likely_intent=intent,
        tactics=tactics,
        finding_explanations=tuple(explanations),
        uncertainty=uncertainty,
        uncertainty_reasons=reasons,
        alternative_explanations=alternatives,
        recommended_actions=actions,
        limitations=(
            "The model sees only supplied message text and local Stage 1 findings.",
            "No remote URL, sender identity, DNS, reputation, or real-world context was verified.",
            "Uncertainty labels are qualitative model judgments, not calibrated probabilities.",
        ),
        model=model,
    )
