"""Stage 2 orchestration. Stage 1 results remain authoritative and unchanged."""

from __future__ import annotations

from typing import Any

from scamsentry.ai.prompts import build_prompt
from scamsentry.ai.provider import AIProvider
from scamsentry.ai.schemas import AIAnalysis, AIOutputValidationError, parse_ai_output


class AIAnalysisError(RuntimeError):
    """AI generation succeeded or failed but could not yield a valid analysis."""


def analyse_with_ai(
    message: str,
    stage1_result: dict[str, Any],
    provider: AIProvider,
    *,
    timeout: int = 120,
) -> AIAnalysis:
    """Interpret Stage 1 evidence without mutating or replacing it."""
    findings = stage1_result.get("findings", [])
    if not isinstance(findings, list):
        raise AIAnalysisError("Stage 1 findings must be a list")
    finding_ids = {
        item["id"] for item in findings
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    prompt = build_prompt(message, stage1_result)
    try:
        raw = provider.generate(prompt, timeout=timeout)
        return parse_ai_output(raw, model=provider.model_name, finding_ids=finding_ids)
    except AIOutputValidationError as exc:
        raise AIAnalysisError(f"Model response failed schema validation: {exc}") from exc
    except AIAnalysisError:
        raise
    except Exception as exc:
        raise AIAnalysisError(f"AI provider failed: {exc}") from exc
