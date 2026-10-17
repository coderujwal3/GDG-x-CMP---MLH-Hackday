from __future__ import annotations

import subprocess

import pytest

from scamsentry.ai.ollama_provider import OllamaProvider
from scamsentry.ai.provider import AIAnalysisError, AIErrorCode


def _completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_missing_ollama_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scamsentry.ai.ollama_provider.shutil.which", lambda _: None)
    provider = OllamaProvider()
    with pytest.raises(AIAnalysisError) as caught:
        provider.generate("prompt")
    assert caught.value.code is AIErrorCode.PROVIDER_UNAVAILABLE


def test_empty_model_name_rejected() -> None:
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider(" ")
    assert caught.value.code is AIErrorCode.INVALID_CONFIGURATION


def test_timeout_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    calls = 0

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _completed("NAME ID SIZE MODIFIED\ngemma3:4b abc 1 GB 1 day ago\n")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr("scamsentry.ai.ollama_provider.subprocess.run", fake_run)
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt", timeout=2)
    assert caught.value.code is AIErrorCode.GENERATION_TIMEOUT
    assert calls == 2


def test_nonzero_model_list_exit_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.subprocess.run",
        lambda *args, **kwargs: _completed(stderr="daemon unavailable", returncode=1),
    )
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.MODEL_EXECUTION_FAILED
    assert caught.value.diagnostic == "daemon unavailable"


def test_nonzero_model_run_exit_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    responses = iter(
        [
            _completed("NAME ID SIZE MODIFIED\ngemma3:4b abc 1 GB 1 day ago\n"),
            _completed(stderr="invalid model response", returncode=1),
        ]
    )
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.subprocess.run",
        lambda *args, **kwargs: next(responses),
    )
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.MODEL_EXECUTION_FAILED
    assert caught.value.diagnostic == "invalid model response"
    assert "invalid model response" not in caught.value.message


def test_missing_installed_model_never_attempts_run_or_pull(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return _completed("NAME ID SIZE MODIFIED\nother:latest 123 1 GB 1 day ago\n")

    monkeypatch.setattr("scamsentry.ai.ollama_provider.subprocess.run", fake_run)
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.MODEL_NOT_INSTALLED
    assert commands == [["/usr/bin/ollama", "list"]]
    assert all("pull" not in command for command in commands)


def test_empty_model_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    responses = iter(
        [
            _completed("NAME ID SIZE MODIFIED\ngemma3:4b abc 1 GB 1 day ago\n"),
            _completed("   \n"),
        ]
    )
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.subprocess.run",
        lambda *args, **kwargs: next(responses),
    )
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.EMPTY_OUTPUT


def test_oversized_model_output_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from scamsentry.ai.ollama_provider import MAX_MODEL_OUTPUT_BYTES

    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    responses = iter(
        [
            _completed("NAME ID SIZE MODIFIED\ngemma3:4b abc 1 GB 1 day ago\n"),
            _completed("x" * (MAX_MODEL_OUTPUT_BYTES + 1)),
        ]
    )
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.subprocess.run",
        lambda *args, **kwargs: next(responses),
    )
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.OUTPUT_TOO_LARGE


def test_success_uses_argument_list_stdin_utf8_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    calls: list[tuple[list[str], dict[str, object]]] = []
    responses = iter(
        [
            _completed("NAME ID SIZE MODIFIED\ngemma3:4b abc 1 GB 1 day ago\n"),
            _completed('{"summary":"Café"}\n'),
        ]
    )

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return next(responses)

    monkeypatch.setattr("scamsentry.ai.ollama_provider.subprocess.run", fake_run)
    prompt = "Analyse this message: café"
    output = OllamaProvider(timeout=60).generate(prompt, timeout=12)
    assert output == '{"summary":"Café"}'
    assert calls[0][0] == ["/usr/bin/ollama", "list"]
    assert calls[1][0] == [
        "/usr/bin/ollama",
        "run",
        "--format",
        "json",
        "--nowordwrap",
        "gemma3:4b",
    ]
    assert calls[1][1]["input"] == prompt
    assert calls[1][1]["encoding"] == "utf-8"
    assert calls[1][1]["shell"] is False
    assert calls[1][1]["timeout"] == 12.0
    assert calls[1][1]["capture_output"] is True


def test_operating_system_error_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.shutil.which", lambda _: "/usr/bin/ollama"
    )
    monkeypatch.setattr(
        "scamsentry.ai.ollama_provider.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("not executable")),
    )
    with pytest.raises(AIAnalysisError) as caught:
        OllamaProvider().generate("prompt")
    assert caught.value.code is AIErrorCode.PROVIDER_UNAVAILABLE
