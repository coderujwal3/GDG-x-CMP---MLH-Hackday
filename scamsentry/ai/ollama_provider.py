"""Cross-platform Ollama CLI provider; no model dependency in Stage 1."""

from __future__ import annotations

import shutil
import subprocess

from scamsentry.ai.provider import AIProvider


class ProviderUnavailableError(RuntimeError):
    """The selected local provider cannot be started or did not respond."""


class OllamaCLIProvider:
    """Run an already-installed Ollama model through its local CLI.

    This provider never downloads models automatically. Install Ollama and pull a
    model explicitly before using it. The CLI is invoked without a shell.
    """

    def __init__(self, model_name: str = "gemma3:4b") -> None:
        self._model_name = model_name.strip()
        if not self._model_name:
            raise ValueError("model_name must not be empty")

    @property
    def model_name(self) -> str:
        return self._model_name

    def generate(self, prompt: str, *, timeout: int = 120) -> str:
        executable = shutil.which("ollama")
        if executable is None:
            raise ProviderUnavailableError(
                "Ollama CLI was not found. Install Ollama and retry with --ai."
            )
        if not isinstance(timeout, int) or timeout < 1 or timeout > 900:
            raise ValueError("timeout must be between 1 and 900 seconds")
        try:
            completed = subprocess.run(
                [executable, "run", self._model_name],
                input=prompt,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProviderUnavailableError(
                f"Ollama did not respond within {timeout} seconds"
            ) from exc
        except OSError as exc:
            raise ProviderUnavailableError(f"Unable to start Ollama: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[:500]
            raise ProviderUnavailableError(
                f"Ollama exited with code {completed.returncode}"
                + (f": {detail}" if detail else "")
            )
        output = completed.stdout.strip()
        if not output:
            raise ProviderUnavailableError("Ollama returned an empty response")
        return output
