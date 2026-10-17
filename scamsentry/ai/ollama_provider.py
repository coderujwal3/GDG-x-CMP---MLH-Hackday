"""Ollama CLI-backed provider; it never installs model weights automatically."""

from __future__ import annotations

import math
import shutil
import subprocess

from scamsentry.ai.provider import AIAnalysisError, AIErrorCode

DEFAULT_MODEL = "gemma3:4b"
DEFAULT_TIMEOUT_SECONDS = 120.0
MAX_MODEL_OUTPUT_BYTES = 32 * 1024
MAX_MODEL_NAME_LENGTH = 128
_DIAGNOSTIC_LIMIT = 240


class OllamaProvider:
    """Run an already-installed Ollama model through its local CLI."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(model, str) or not model.strip():
            raise AIAnalysisError(
                "Model name must not be empty.",
                code=AIErrorCode.INVALID_CONFIGURATION,
                model_id=model if isinstance(model, str) else None,
            )
        if len(model) > MAX_MODEL_NAME_LENGTH:
            raise AIAnalysisError(
                f"Model name exceeds the {MAX_MODEL_NAME_LENGTH}-character limit.",
                code=AIErrorCode.INVALID_CONFIGURATION,
            )
        if model != model.strip() or any(char.isspace() or ord(char) < 32 for char in model):
            raise AIAnalysisError(
                "Model name must not contain whitespace or control characters.",
                code=AIErrorCode.INVALID_CONFIGURATION,
                model_id=model,
            )
        if model.startswith("-"):
            raise AIAnalysisError(
                "Model name must not start with a command-line option prefix.",
                code=AIErrorCode.INVALID_CONFIGURATION,
                model_id=model,
            )
        self._model = model
        self._timeout = self._validate_timeout(timeout)

    @property
    def model_id(self) -> str:
        return self._model

    @staticmethod
    def _validate_timeout(timeout: float) -> float:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise AIAnalysisError(
                "Timeout must be a finite positive number of seconds.",
                code=AIErrorCode.INVALID_CONFIGURATION,
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise AIAnalysisError(
                "Timeout must be a finite positive number of seconds.",
                code=AIErrorCode.INVALID_CONFIGURATION,
            )
        return float(timeout)

    @staticmethod
    def _bounded_diagnostic(value: str) -> str:
        compact = " ".join(value.split())
        if len(compact) > _DIAGNOSTIC_LIMIT:
            return compact[: _DIAGNOSTIC_LIMIT - 1] + "…"
        return compact

    def _find_executable(self) -> str:
        executable = shutil.which("ollama")
        if executable is None:
            raise AIAnalysisError(
                "Ollama CLI was not found; install Ollama and make it available on PATH.",
                code=AIErrorCode.PROVIDER_UNAVAILABLE,
                model_id=self.model_id,
            )
        return executable

    def _run(
        self,
        command: list[str],
        *,
        timeout: float,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AIAnalysisError(
                f"Ollama did not finish within {timeout:g} seconds.",
                code=AIErrorCode.GENERATION_TIMEOUT,
                model_id=self.model_id,
            ) from exc
        except OSError as exc:
            diagnostic = self._bounded_diagnostic(exc.strerror or str(exc))
            raise AIAnalysisError(
                "Unable to execute Ollama CLI.",
                code=AIErrorCode.PROVIDER_UNAVAILABLE,
                model_id=self.model_id,
                diagnostic=diagnostic,
            ) from exc

    def generate(self, prompt: str, *, timeout: float | None = None) -> str:
        if not isinstance(prompt, str):
            raise AIAnalysisError(
                "Prompt must be text.",
                code=AIErrorCode.INVALID_CONFIGURATION,
                model_id=self.model_id,
            )
        effective_timeout = self._timeout if timeout is None else self._validate_timeout(timeout)
        executable = self._find_executable()

        listing = self._run([executable, "list"], timeout=effective_timeout)
        if listing.returncode != 0:
            diagnostic = self._bounded_diagnostic(listing.stderr)
            raise AIAnalysisError(
                "Unable to list installed Ollama models.",
                code=AIErrorCode.MODEL_EXECUTION_FAILED,
                model_id=self.model_id,
                diagnostic=diagnostic or None,
            )

        installed = {
            line.split()[0]
            for line in listing.stdout.splitlines()[1:]
            if line.split()
        }
        if self.model_id not in installed:
            raise AIAnalysisError(
                f"Model {self.model_id!r} is not installed; install it explicitly with "
                f"`ollama pull {self.model_id}`.",
                code=AIErrorCode.MODEL_NOT_INSTALLED,
                model_id=self.model_id,
            )

        response = self._run(
            [
                executable,
                "run",
                "--format",
                "json",
                "--nowordwrap",
                self.model_id,
            ],
            timeout=effective_timeout,
            input_text=prompt,
        )
        if response.returncode != 0:
            diagnostic = self._bounded_diagnostic(response.stderr)
            raise AIAnalysisError(
                "Ollama model execution failed.",
                code=AIErrorCode.MODEL_EXECUTION_FAILED,
                model_id=self.model_id,
                diagnostic=diagnostic or None,
            )
        if not response.stdout.strip():
            raise AIAnalysisError(
                "Ollama returned empty output.",
                code=AIErrorCode.EMPTY_OUTPUT,
                model_id=self.model_id,
            )
        if len(response.stdout.encode("utf-8")) > MAX_MODEL_OUTPUT_BYTES:
            raise AIAnalysisError(
                f"Ollama output exceeded the {MAX_MODEL_OUTPUT_BYTES}-byte limit.",
                code=AIErrorCode.OUTPUT_TOO_LARGE,
                model_id=self.model_id,
            )
        return response.stdout.strip()
