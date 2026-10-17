"""ScamSentry AI Stage 1: deterministic, offline message analysis."""

from scamsentry.analyzer import analyse_file, analyse_message
from scamsentry.models import (
    AnalysisResult,
    AnalysisStatus,
    EvidenceSource,
    Finding,
    InputError,
    ObservationKind,
    RiskBand,
    ScamSentryError,
    SCHEMA_VERSION,
)

__all__ = [
    "SCHEMA_VERSION",
    "AnalysisResult",
    "AnalysisStatus",
    "EvidenceSource",
    "Finding",
    "InputError",
    "ObservationKind",
    "RiskBand",
    "ScamSentryError",
    "analyse_file",
    "analyse_message",
]

__version__ = "0.1.0"
