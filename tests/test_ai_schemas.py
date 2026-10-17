from __future__ import annotations

import json

import pytest

from scamsentry.ai.ollama_provider import MAX_MODEL_OUTPUT_BYTES
from scamsentry.ai.provider import AIAnalysisError, AIErrorCode
from scamsentry.ai.schemas import (
    AI_SCHEMA_VERSION,
    LikelyIntent,
    Tactic,
    Uncertainty,
    parse_ai_response,
)

FINDING_IDS = {"F001", "F002"}


def _payload() -> dict:
    return {
        "summary": "The message requests account credentials.",
        "likely_intent": "obtain_credentials",
        "tactics": ["credential_harvesting"],
        "finding_explanations": [
            {
                "finding_id": "F001",
                "interpretation": "This may indicate an attempt to collect credentials.",
            }
        ],
        "uncertainty": "moderate",
        "uncertainty_reasons": [],
        "alternative_explanations": ["A legitimate notice remains possible."],
        "recommended_actions": ["Verify through the official application."],
    }


def _parse(payload: dict | None = None):
    return parse_ai_response(
        json.dumps(_payload() if payload is None else payload),
        valid_finding_ids=FINDING_IDS,
        model_id="gemma3:4b",
    )


def test_valid_response_is_converted_to_typed_analysis() -> None:
    result = _parse()
    assert result.likely_intent is LikelyIntent.OBTAIN_CREDENTIALS
    assert result.tactics == (Tactic.CREDENTIAL_HARVESTING,)
    assert result.uncertainty is Uncertainty.MODERATE
    assert result.schema_version == AI_SCHEMA_VERSION
    assert result.to_dict()["model"] == "gemma3:4b"
    assert result.to_dict()["advisory"]


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("{not json", AIErrorCode.INVALID_JSON),
        ("[]", AIErrorCode.INVALID_SCHEMA),
    ],
)
def test_invalid_json_and_non_object_are_rejected(raw: str, code: AIErrorCode) -> None:
    with pytest.raises(AIAnalysisError) as caught:
        parse_ai_response(raw, valid_finding_ids=FINDING_IDS, model_id="model")
    assert caught.value.code is code


def test_duplicate_json_object_keys_are_rejected() -> None:
    raw = '{"summary":"first","summary":"second"}'
    with pytest.raises(AIAnalysisError, match="duplicate"):
        parse_ai_response(raw, valid_finding_ids=FINDING_IDS, model_id="model")


def test_missing_and_unexpected_fields_are_rejected() -> None:
    missing = _payload()
    del missing["summary"]
    with pytest.raises(AIAnalysisError, match="missing"):
        _parse(missing)
    extra = _payload()
    extra["confidence"] = 0.99
    with pytest.raises(AIAnalysisError, match="unexpected"):
        _parse(extra)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("likely_intent", "verified_scam"),
        ("tactics", ["unknown_tactic"]),
        ("uncertainty", "certain"),
    ],
)
def test_unknown_taxonomy_labels_rejected(field: str, value: object) -> None:
    payload = _payload()
    payload[field] = value
    with pytest.raises(AIAnalysisError):
        _parse(payload)


def test_unknown_and_duplicate_finding_ids_rejected() -> None:
    unknown = _payload()
    unknown["finding_explanations"][0]["finding_id"] = "F999"
    with pytest.raises(AIAnalysisError, match="unknown"):
        _parse(unknown)
    duplicate = _payload()
    duplicate["finding_explanations"].append(
        {"finding_id": "F001", "interpretation": "A second explanation."}
    )
    with pytest.raises(AIAnalysisError, match="more than once"):
        _parse(duplicate)


def test_invalid_string_types_empty_strings_and_excessive_strings_rejected() -> None:
    wrong_type = _payload()
    wrong_type["summary"] = 3
    with pytest.raises(AIAnalysisError, match="string"):
        _parse(wrong_type)
    empty = _payload()
    empty["summary"] = " "
    with pytest.raises(AIAnalysisError, match="empty"):
        _parse(empty)
    long_text = _payload()
    long_text["summary"] = "x" * 801
    with pytest.raises(AIAnalysisError, match="limit"):
        _parse(long_text)


def test_excessive_lists_and_output_length_rejected() -> None:
    too_many = _payload()
    too_many["alternative_explanations"] = [f"reason {i}" for i in range(9)]
    with pytest.raises(AIAnalysisError, match="between"):
        _parse(too_many)
    with pytest.raises(AIAnalysisError) as caught:
        parse_ai_response(
            " " * (MAX_MODEL_OUTPUT_BYTES + 1),
            valid_finding_ids=FINDING_IDS,
            model_id="model",
        )
    assert caught.value.code is AIErrorCode.OUTPUT_TOO_LARGE


def test_high_uncertainty_requires_reasons() -> None:
    payload = _payload()
    payload["uncertainty"] = "high"
    payload["uncertainty_reasons"] = []
    with pytest.raises(AIAnalysisError, match="requires"):
        _parse(payload)


def test_valid_unable_to_assess_output() -> None:
    payload = _payload()
    payload["likely_intent"] = "unclear"
    payload["tactics"] = ["none_observed"]
    payload["finding_explanations"] = []
    payload["uncertainty"] = "unable_to_assess"
    payload["uncertainty_reasons"] = ["The message lacks sender and surrounding context."]
    result = _parse(payload)
    assert result.uncertainty is Uncertainty.UNABLE_TO_ASSESS
    assert result.likely_intent is LikelyIntent.UNCLEAR
    assert result.finding_explanations == ()


def test_empty_or_inconsistent_tactic_list_is_rejected() -> None:
    empty = _payload()
    empty["tactics"] = []
    with pytest.raises(AIAnalysisError):
        _parse(empty)
    inconsistent = _payload()
    inconsistent["tactics"] = ["none_observed", "fear_or_threat"]
    with pytest.raises(AIAnalysisError, match="cannot be combined"):
        _parse(inconsistent)
