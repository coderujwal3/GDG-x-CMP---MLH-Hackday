from __future__ import annotations

import json
import pytest
from scamsentry.ai.schemas import AIOutputValidationError, parse_ai_output


def payload(**overrides):
    value = {
        "summary": "The message uses account pressure and requests a password.",
        "likely_intent": "obtain_credentials",
        "tactics": ["urgency_or_time_pressure", "credential_harvesting"],
        "finding_explanations": [{"finding_id": "F001", "interpretation": "The wording pressures the recipient."}],
        "uncertainty": "moderate",
        "uncertainty_reasons": ["The sender and destination were not verified."],
        "alternative_explanations": ["A legitimate service notice is possible."],
        "recommended_actions": ["Open the service through a known official app."],
    }
    value.update(overrides)
    return value


def test_parse_valid_response():
    result = parse_ai_output(json.dumps(payload()), model="gemma3:4b", finding_ids={"F001"})
    assert result.likely_intent == "obtain_credentials"
    assert result.tactics == ("urgency_or_time_pressure", "credential_harvesting")
    assert result.to_dict()["status"] == "complete"


@pytest.mark.parametrize("raw", ["not json", "[]", "null", ""])
def test_rejects_non_object_or_invalid_json(raw):
    with pytest.raises(AIOutputValidationError):
        parse_ai_output(raw, model="test", finding_ids={"F001"})


def test_rejects_unknown_fields():
    value = payload()
    value["risk_score"] = 0.99
    with pytest.raises(AIOutputValidationError, match="Incorrect fields"):
        parse_ai_output(json.dumps(value), model="test", finding_ids={"F001"})


def test_rejects_unknown_finding_id():
    with pytest.raises(AIOutputValidationError, match="Unknown finding_id"):
        parse_ai_output(json.dumps(payload()), model="test", finding_ids=set())


def test_rejects_invalid_tactic():
    with pytest.raises(AIOutputValidationError, match="Unknown tactic"):
        parse_ai_output(json.dumps(payload(tactics=["guaranteed_scam"])), model="test", finding_ids={"F001"})


def test_high_uncertainty_requires_reason():
    with pytest.raises(AIOutputValidationError, match="requires reasons"):
        parse_ai_output(json.dumps(payload(uncertainty="high", uncertainty_reasons=[])), model="test", finding_ids={"F001"})


def test_rejects_oversized_output():
    with pytest.raises(AIOutputValidationError, match="exceeds"):
        parse_ai_output("x" * 20001, model="test", finding_ids=set())
