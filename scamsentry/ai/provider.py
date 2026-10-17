"""Provider contract for optional open-weight language models."""

from __future__ import annotations

from typing import Protocol


class AIProvider(Protocol):
    """Minimal provider interface; implementations return raw model text."""

    @property
    def model_name(self) -> str:
        """Human-readable model identifier."""

    def generate(self, prompt: str, *, timeout: int = 120) -> str:
        """Generate a response for a prompt or raise a provider-specific error."""
