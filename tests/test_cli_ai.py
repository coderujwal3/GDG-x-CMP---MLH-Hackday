from __future__ import annotations

import io
import json

import pytest

from scamsentry.cli import run


def _run(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run(argv, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def _valid_output() -> str:
    return json.dumps(
        {
            "summary": "The note is likely informational but cannot be verified.",
            "likely_intent": "benign_or_informational",
            "tactics": ["none_observed"],
            "finding_explanations": [],
            "uncertainty": "moderate",
            "uncertainty_reasons": ["The sender is unknown."],
            "alternative_explanations": ["It may be an ordinary notification."],
            "recommended_actions": ["Verify using a known channel if unexpected."],
        }
    )


def _output_with_explanations(*finding_ids: str) -> str:
    payload = json.loads(_valid_output())
    payload["finding_explanations"] = [
        {
            "finding_id": finding_id,
            "interpretation": "This contextual interpretation relates to one finding.",
        }
        for finding_id in finding_ids
    ]
    return json.dumps(payload)


def test_stage1_only_does_not_initialize_ai_provider() -> None:
    code, output, stderr = _run(
        ["analyze", "--text", "hello there colleague", "--json"]
    )
    assert code == 0
    assert stderr == ""
    payload = json.loads(output)
    assert "ai_analysis" not in payload
    assert "decision" not in payload
    assert payload["risk_band"] == "LOW_CONCERN"


def test_ai_flag_calls_provider_and_model_timeout_are_respected(
    monkeypatch,
) -> None:
    import scamsentry.ai.ollama_provider as ollama_module
    from scamsentry.analyzer import analyse_message

    calls: list[tuple[str, float]] = []

    class FakeOllamaProvider:
        def __init__(self, model: str, *, timeout: float) -> None:
            calls.append((model, timeout))
            self.model_id = model

        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            calls.append((self.model_id, timeout or 0.0))
            return _valid_output()

    monkeypatch.setattr(ollama_module, "OllamaProvider", FakeOllamaProvider)
    message = "hello there"
    code, output, stderr = _run(
        [
            "analyze",
            "--text",
            message,
            "--ai",
            "--ai-model",
            "custom:tag",
            "--ai-timeout",
            "9.5",
            "--json",
        ]
    )
    assert code == 0
    assert stderr == ""
    assert calls == [("custom:tag", 9.5), ("custom:tag", 9.5)]
    payload = json.loads(output)
    assert payload["ai_analysis"]["status"] == "complete"
    assert payload["ai_analysis"]["model"] == "custom:tag"
    assert payload["risk_band"] == "LOW_CONCERN"
    assert payload["decision"]["final_risk_band"] == "INCONCLUSIVE"
    assert payload["decision"]["ai_status"] == "complete"
    expected_stage1 = analyse_message(message).to_dict()
    assert {key: payload[key] for key in expected_stage1} == expected_stage1


def test_invalid_timeout_is_usage_error() -> None:
    code, output, stderr = _run(
        ["analyze", "--text", "hi", "--ai", "--ai-timeout", "0", "--json"]
    )
    assert code == 2
    assert "finite positive" in stderr
    assert json.loads(output)["analysis_status"] == "input_error"


@pytest.mark.parametrize(
    ("finding_ids", "expected_status", "expected_decision_status"),
    [
        (("F001",), "complete", "complete"),
        (("F001", "F001"), "invalid", "invalid"),
    ],
)
def test_original_url_cli_scenario_preserves_stage1_and_decides_without_model_download(
    monkeypatch,
    finding_ids: tuple[str, ...],
    expected_status: str,
    expected_decision_status: str,
) -> None:
    import scamsentry.ai.ollama_provider as ollama_module
    from scamsentry.analyzer import analyse_message

    prompts: list[str] = []

    class FakeOllamaProvider:
        model_id = "fake-local-model"

        def __init__(self, model: str, *, timeout: float) -> None:
            self.model_id = model

        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            prompts.append(prompt)
            return _output_with_explanations(*finding_ids)

    monkeypatch.setattr(ollama_module, "OllamaProvider", FakeOllamaProvider)
    message = "https://paypal.unrelated-example.test/verify"
    code, output, stderr = _run(
        ["analyze", "--text", message, "--ai", "--json"]
    )

    assert code == 0
    payload = json.loads(output)
    expected_stage1 = analyse_message(message).to_dict()
    assert {key: payload[key] for key in expected_stage1} == expected_stage1
    assert payload["findings"][0]["id"] == "F001"
    assert payload["findings"][0]["severity"] == "HIGH"
    assert payload["risk_band"] == "REVIEW"
    assert payload["ai_analysis"]["status"] == expected_status
    assert payload["decision"]["ai_status"] == expected_decision_status
    assert payload["decision"]["stage1_risk_band"] == "REVIEW"
    assert payload["decision"]["final_risk_band"] == "REVIEW"
    assert payload["decision"]["risk_policy_version"] == "1.0"
    assert "HIGH finding alone" in payload["decision"]["rationale"]
    assert len(prompts) == 1
    assert prompts[0] not in output + stderr

    if expected_status == "complete":
        assert stderr == ""
        assert payload["ai_analysis"]["finding_explanations"] == [
            {
                "finding_id": "F001",
                "interpretation": "This contextual interpretation relates to one finding.",
            }
        ]
    else:
        assert "warning: AI interpretation invalid (invalid_schema)" in stderr
        assert "A Stage 1 finding ID is explained more than once." in stderr
        assert message not in stderr
        assert payload["ai_analysis"]["error"]["code"] == "invalid_schema"
        assert payload["decision"]["uncertainty"] == "high"


def test_original_url_human_output_separates_stages_and_keeps_prompt_private(
    monkeypatch,
) -> None:
    import scamsentry.ai.ollama_provider as ollama_module

    prompts: list[str] = []

    class DuplicateExplanationProvider:
        model_id = "fake-local-model"

        def __init__(self, model: str, *, timeout: float) -> None:
            self.model_id = model

        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            prompts.append(prompt)
            return _output_with_explanations("F001", "F001")

    monkeypatch.setattr(ollama_module, "OllamaProvider", DuplicateExplanationProvider)
    message = "https://paypal.unrelated-example.test/verify"
    code, output, stderr = _run(["analyze", "--text", message, "--ai"])

    assert code == 0
    assert "[F001] E_MISLEADING_HOST — HIGH / url (heuristic)" in output
    assert "Stage 1 risk band: REVIEW" in output
    assert "1. Stage 1 deterministic analysis" in output
    assert "Stage 2 AI interpretation (advisory):" in output
    assert "Invalid (invalid_schema)" in output
    assert "Stage 3 deterministic decision:" in output
    assert "Final risk band: REVIEW" in output
    assert "HIGH finding alone does not meet" in " ".join(output.split())
    assert "Uncertainty and incomplete-check notes:" in output
    assert message not in stderr
    assert prompts[0] not in output + stderr
    assert output.index("1. Stage 1 deterministic analysis") < output.index(
        "2. Stage 2 AI interpretation"
    ) < output.index("3. Stage 3 deterministic decision")


def test_ai_failure_keeps_json_stage1_and_emits_warning_to_stderr(
    monkeypatch,
) -> None:
    import scamsentry.ai.ollama_provider as ollama_module
    from scamsentry.ai.provider import AIAnalysisError, AIErrorCode
    from scamsentry.analyzer import analyse_message

    class MissingProvider:
        def __init__(self, model: str, *, timeout: float) -> None:
            raise AIAnalysisError(
                "Ollama CLI was not found.",
                code=AIErrorCode.PROVIDER_UNAVAILABLE,
                model_id=model,
            )

    monkeypatch.setattr(ollama_module, "OllamaProvider", MissingProvider)
    message = "Your account is suspended."
    code, output, stderr = _run(["analyze", "--text", message, "--ai", "--json"])
    assert code == 0
    assert "warning: AI interpretation unavailable" in stderr
    payload = json.loads(output)
    expected_stage1 = analyse_message(message).to_dict()
    assert {key: payload[key] for key in expected_stage1} == expected_stage1
    assert payload["analysis_status"] == "complete"
    assert payload["ai_analysis"]["status"] == "unavailable"
    assert payload["ai_analysis"]["error"]["code"] == "provider_unavailable"
    assert payload["decision"]["ai_status"] == "unavailable"
    assert payload["decision"]["final_risk_band"] == "REVIEW"


def test_human_output_separates_stages(
    monkeypatch,
) -> None:
    import scamsentry.ai.ollama_provider as ollama_module

    class FakeOllamaProvider:
        def __init__(self, model: str, *, timeout: float) -> None:
            self.model_id = model

        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            return _valid_output()

    monkeypatch.setattr(ollama_module, "OllamaProvider", FakeOllamaProvider)
    code, output, stderr = _run(
        ["analyze", "--text", "hello", "--ai"]
    )
    assert code == 0
    assert stderr == ""
    assert "Stage 1 deterministic analysis" in output
    assert "Stage 2 AI interpretation (advisory)" in output
    assert "Stage 3 deterministic decision" in output
    assert "Stage 1 risk band: LOW_CONCERN" in output
    assert "Final risk band: INCONCLUSIVE" in output
    assert "Recommended actions:" in output
    assert "Advisory model interpretation only" in output


def test_decision_flag_adds_stage3_without_starting_ai() -> None:
    code, output, stderr = _run(
        ["analyze", "--text", "hello there colleague", "--decision", "--json"]
    )
    assert code == 0
    assert stderr == ""
    payload = json.loads(output)
    assert "ai_analysis" not in payload
    assert payload["decision"]["ai_status"] == "not_requested"
    assert payload["decision"]["final_risk_band"] == "INCONCLUSIVE"


def test_ai_failure_human_output_reports_stage3(monkeypatch) -> None:
    import scamsentry.ai.ollama_provider as ollama_module
    from scamsentry.ai.provider import AIAnalysisError, AIErrorCode

    class MissingProvider:
        def __init__(self, model: str, *, timeout: float) -> None:
            raise AIAnalysisError(
                "Ollama CLI was not found.",
                code=AIErrorCode.PROVIDER_UNAVAILABLE,
                model_id=model,
            )

    monkeypatch.setattr(ollama_module, "OllamaProvider", MissingProvider)
    code, output, _ = _run(["analyze", "--text", "Your account is suspended.", "--ai"])
    assert code == 0
    assert "Final risk band: REVIEW" in output
    assert "Stage 2 was unavailable" in output


def test_json_ai_failure_remains_machine_readable(monkeypatch) -> None:
    import scamsentry.ai.ollama_provider as ollama_module
    from scamsentry.ai.provider import AIAnalysisError, AIErrorCode

    class InvalidProvider:
        def __init__(self, model: str, *, timeout: float) -> None:
            self.model_id = model

        def generate(self, prompt: str, *, timeout: float | None = None) -> str:
            raise AIAnalysisError(
                "bad model output",
                code=AIErrorCode.INVALID_JSON,
                model_id=self.model_id,
            )

    monkeypatch.setattr(ollama_module, "OllamaProvider", InvalidProvider)
    code, output, stderr = _run(
        ["analyze", "--text", "hello", "--ai", "--json"]
    )
    assert code == 0
    assert stderr.startswith("warning:")
    payload = json.loads(output)
    assert payload["ai_analysis"]["status"] == "invalid"
    assert payload["risk_band"] == "LOW_CONCERN"
