from __future__ import annotations

import json

import pytest

from scamsentry.analyzer import analyse_message
from scamsentry.ai.analysis import analyse_with_ai
from scamsentry.ai.provider import AIAnalysisError, AIErrorCode


def _valid_output() -> str:
    return json.dumps(
        {
            "summary": "The message requests a password and applies urgency.",
            "likely_intent": "obtain_credentials",
            "tactics": ["credential_harvesting", "urgency_or_time_pressure"],
            "finding_explanations": [
                {
                    "finding_id": "F001",
                    "interpretation": "A password request may expose credentials.",
                }
            ],
            "uncertainty": "moderate",
            "uncertainty_reasons": [],
            "alternative_explanations": ["A legitimate account notice is possible."],
            "recommended_actions": ["Check via the official application."],
        }
    )


class FakeProvider:
    model_id = "fake-local-model"

    def __init__(self, output: str = _valid_output()) -> None:
        self.output = output
        self.prompt: str | None = None
        self.timeout: float | None = None

    def generate(self, prompt: str, *, timeout: float | None = None) -> str:
        self.prompt = prompt
        self.timeout = timeout
        return self.output


def test_provider_invocation_and_model_name_propagate() -> None:
    message = "Your account is suspended. Enter your password now."
    stage1 = analyse_message(message)
    provider = FakeProvider()
    result = analyse_with_ai(message, stage1, provider, timeout=8.5)
    assert provider.prompt is not None
    assert message in provider.prompt
    assert provider.timeout == 8.5
    assert result.model == "fake-local-model"
    assert result.finding_explanations[0].finding_id == "F001"


def test_stage1_result_is_unchanged_after_successful_ai_analysis() -> None:
    message = "Your account is suspended. Enter your password now."
    stage1 = analyse_message(message)
    before = stage1.to_dict()
    ai = analyse_with_ai(message, stage1, FakeProvider())
    assert ai.status == "complete"
    assert stage1.to_dict() == before


def test_invalid_output_is_rejected_and_stage1_is_unchanged() -> None:
    message = "Your account is suspended. Enter your password now."
    stage1 = analyse_message(message)
    before = stage1.to_dict()
    with pytest.raises(AIAnalysisError) as caught:
        analyse_with_ai(message, stage1, FakeProvider("not json"))
    assert caught.value.code is AIErrorCode.INVALID_JSON
    assert stage1.to_dict() == before


def test_duplicate_finding_explanations_are_rejected_without_changing_stage1() -> None:
    message = "Your account is suspended. Enter your password now."
    stage1 = analyse_message(message)
    before = stage1.to_dict()
    output = json.loads(_valid_output())
    output["finding_explanations"].append(
        {
            "finding_id": "F001",
            "interpretation": "A second observation about the same finding.",
        }
    )
    with pytest.raises(AIAnalysisError, match="explained more than once") as caught:
        analyse_with_ai(message, stage1, FakeProvider(json.dumps(output)))
    assert caught.value.code is AIErrorCode.INVALID_SCHEMA
    assert stage1.to_dict() == before


def test_provider_exception_is_normalized() -> None:
    class BrokenProvider(FakeProvider):
        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            raise RuntimeError("private prompt must not appear in error")

    message = "ordinary note"
    with pytest.raises(AIAnalysisError) as caught:
        analyse_with_ai(message, analyse_message(message), BrokenProvider())
    assert caught.value.code is AIErrorCode.INTERNAL_ERROR
    assert "private prompt" not in caught.value.message


def test_no_findings_can_be_assessed_without_claiming_safety() -> None:
    message = "Hello, the meeting is at noon."
    stage1 = analyse_message(message)
    assert stage1.findings == []
    provider = FakeProvider(
        json.dumps(
            {
                "summary": "A brief meeting reminder is present.",
                "likely_intent": "benign_or_informational",
                "tactics": ["none_observed"],
                "finding_explanations": [],
                "uncertainty": "moderate",
                "uncertainty_reasons": ["The sender identity is unavailable."],
                "alternative_explanations": ["Context around the message may be missing."],
                "recommended_actions": ["Confirm the meeting using a known channel."],
            }
        )
    )
    ai = analyse_with_ai(message, stage1, provider)
    assert ai.finding_explanations == ()
    assert ai.uncertainty_reasons
    assert "not evidence that the message is safe" in (provider.prompt or "")


def test_incomplete_stage1_checks_are_supplied_to_model() -> None:
    message = "Please review the notice."
    stage1 = analyse_message(message)
    provider = FakeProvider(
        json.dumps(
            {
                "summary": "The message asks for a review without enough context.",
                "likely_intent": "unclear",
                "tactics": ["none_observed"],
                "finding_explanations": [],
                "uncertainty": "high",
                "uncertainty_reasons": ["The sender and surrounding context are unknown."],
                "alternative_explanations": ["It may be an ordinary notification."],
                "recommended_actions": ["Verify through a known channel."],
            }
        )
    )
    analyse_with_ai(message, stage1, provider)
    assert "dns_resolution" in (provider.prompt or "")


def test_message_must_match_supplied_stage1_result() -> None:
    result = analyse_message("message one")
    with pytest.raises(AIAnalysisError, match="does not match"):
        analyse_with_ai("message two", result, FakeProvider())
