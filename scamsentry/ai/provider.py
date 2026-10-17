"""Provider contract and errors for optional AI analysis."""

from __future__ import annotations

from enum import Enum
from typing import Protocol


class AIErrorCode(str, Enum):
    INVALID_CONFIGURATION = "invalid_configuration"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    MODEL_NOT_INSTALLED = "model_not_installed"
    GENERATION_TIMEOUT = "generation_timeout"
    MODEL_EXECUTION_FAILED = "model_execution_failed"
    EMPTY_OUTPUT = "empty_output"
    INVALID_JSON = "invalid_json"
    INVALID_SCHEMA = "invalid_schema"
    OUTPUT_TOO_LARGE = "output_too_large"
    INTERNAL_ERROR = "internal_error"


class AIAnalysisError(Exception):
    """Expected failure from provider execution or AI-output validation."""

    def __init__(
        self,
        message: str,
        *,
        code: AIErrorCode,
        model_id: str | None = None,
        diagnostic: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.model_id = model_id
        self.diagnostic = diagnostic


class AIProvider(Protocol):
    """Small extension point for local text-generation runtimes."""

    @property
    def model_id(self) -> str:
        """Human-readable identifier for the configured model."""

    def generate(self, prompt: str, *, timeout: float | None = None) -> str:
        """Generate text, enforcing the supplied per-call timeout."""
