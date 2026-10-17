"""Deterministic validation, fusion, risk assessment, and recommendations."""

from scamsentry.decision.fusion import assess
from scamsentry.decision.models import DecisionResult

__all__ = ["DecisionResult", "assess"]
