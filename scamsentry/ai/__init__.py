"""Optional open-weight AI analysis for ScamSentry Stage 2.

Importing this package does not load a model or contact a service.
"""

from scamsentry.ai.analysis import AIAnalysisError, analyse_with_ai
from scamsentry.ai.ollama_provider import OllamaCLIProvider, ProviderUnavailableError
from scamsentry.ai.schemas import AIAnalysis

__all__ = [
    "AIAnalysis",
    "AIAnalysisError",
    "OllamaCLIProvider",
    "ProviderUnavailableError",
    "analyse_with_ai",
]
