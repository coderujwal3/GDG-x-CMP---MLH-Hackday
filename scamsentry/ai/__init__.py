"""Optional local-model interpretation for Stage 1 results."""

from scamsentry.ai.analysis import analyse_with_ai
from scamsentry.ai.ollama_provider import (
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT_SECONDS,
    OllamaProvider,
)
from scamsentry.ai.schemas import AIAnalysis

__all__ = [
    "AIAnalysis",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT_SECONDS",
    "OllamaProvider",
    "analyse_with_ai",
]
