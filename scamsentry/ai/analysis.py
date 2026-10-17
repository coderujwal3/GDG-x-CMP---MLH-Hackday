"""Stage 2 orchestration, independent of any specific model runtime."""

from __future__ import annotations

from scamsentry.ai.prompts import build_prompt
from scamsentry.ai.provider import AIAnalysisError, AIErrorCode, AIProvider
from scamsentry.ai.schemas import AIAnalysis, parse_ai_response
from scamsentry.models import AnalysisResult


def analyse_with_ai(
    message: str,
    stage1_result: AnalysisResult,
    provider: AIProvider,
    *,
    timeout: float | None = None,
) -> AIAnalysis:
    """Interpret a Stage 1 result without mutating or replacing it."""

    if message != stage1_result.original_message:
        raise AIAnalysisError(
            "Message does not match the supplied Stage 1 result.",
            code=AIErrorCode.INVALID_CONFIGURATION,
            model_id=provider.model_id,
        )
    try:
        prompt = build_prompt(message, stage1_result)
        raw_output = provider.generate(prompt, timeout=timeout)
        return parse_ai_response(
            raw_output,
            valid_finding_ids={finding.id for finding in stage1_result.findings},
            model_id=provider.model_id,
        )
    except AIAnalysisError:
        raise
    except Exception as exc:
        raise AIAnalysisError(
            "AI analysis failed unexpectedly; the Stage 1 result is unchanged.",
            code=AIErrorCode.INTERNAL_ERROR,
            model_id=provider.model_id,
        ) from exc
