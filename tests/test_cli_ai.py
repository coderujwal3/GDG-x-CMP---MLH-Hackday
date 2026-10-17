from __future__ import annotations

import io
import json

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
    assert payload["ai_analysis"]["status"] == "unavailable"
    assert payload["risk_band"] == "LOW_CONCERN"
