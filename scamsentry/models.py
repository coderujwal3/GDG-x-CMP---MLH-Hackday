"""Typed evidence schema for Stage 1 deterministic analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


SCHEMA_VERSION = "1.0"

DEFAULT_MAX_BYTES = 50 * 1024

STANDARD_LIMITATIONS: tuple[str, ...] = (
    "Offline inspection cannot establish whether a remote site is currently malicious.",
    "Findings are named heuristics and observed patterns, not proof that a message is a scam.",
    "Absence of findings is not proof that a message is safe; unimplemented checks did not fire.",
    "No DNS, HTTP, redirect, JavaScript, metadata, or reputation lookups are performed.",
    "No language model is used in Stage 1; missing model output is not a safety signal.",
    "Risk bands are a transparent rule-based policy, not a calibrated probability or verified reputation score.",
)


class ScamSentryError(Exception):
    """Base error for ScamSentry."""


class InputError(ScamSentryError):
    """Invalid user input (empty, oversized, unreadable, or malformed)."""


class Category(str, Enum):
    URGENCY = "urgency"
    CREDENTIAL = "credential"
    PAYMENT = "payment"
    IMPERSONATION = "impersonation"
    URL = "url"
    FORMATTING = "formatting"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class EvidenceSource(str, Enum):
    ORIGINAL = "original"
    NORMALISED = "normalised"
    URL_COMPONENT = "url_component"


class ObservationKind(str, Enum):
    DIRECT = "direct"
    HEURISTIC = "heuristic"


class FindingSource(str, Enum):
    DETERMINISTIC = "deterministic"
    MODEL = "model"


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    INPUT_ERROR = "input_error"


class RiskBand(str, Enum):
    LOW_CONCERN = "LOW_CONCERN"
    REVIEW = "REVIEW"
    HIGH_CONCERN = "HIGH_CONCERN"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Finding:
    """A single named observation. Not conclusive proof of a scam."""

    id: str
    rule_id: str
    category: Category
    severity: Severity
    title: str
    evidence_text: str
    evidence_source: EvidenceSource
    explanation: str
    observation_kind: ObservationKind
    source: FindingSource = FindingSource.DETERMINISTIC
    start_offset: int | None = None
    end_offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "evidence_text": self.evidence_text,
            "evidence_source": self.evidence_source.value,
            "explanation": self.explanation,
            "observation_kind": self.observation_kind.value,
            "source": self.source.value,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
        }


@dataclass
class AnalysisResult:
    """Structured analysis output. JSON-serialisable and ordered deterministically."""

    original_message: str
    normalised_message: str
    findings: list[Finding]
    analysis_status: AnalysisStatus
    risk_band: RiskBand | None
    checks_performed: tuple[str, ...]
    checks_incomplete: tuple[str, ...]
    limitations: tuple[str, ...] = STANDARD_LIMITATIONS
    schema_version: str = SCHEMA_VERSION
    risk_policy: str = (
        "Heuristic triage policy (not calibrated probability or proof of fraud): "
        "LOW_CONCERN if zero findings; HIGH_CONCERN requires at least two genuinely "
        "independent categories with at least one HIGH finding (correlated pairs such as "
        "brand impersonation derived solely from urgency do not count as independent); "
        "otherwise REVIEW if any finding is present; INCONCLUSIVE if analysis failed or "
        "was incomplete. Duplicate findings and repeated matches within the same category "
        "do not inflate the risk band. Invalid input is an error, not a risk band."
    )
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analysis_status": self.analysis_status.value,
            "risk_band": None if self.risk_band is None else self.risk_band.value,
            "finding_count": self.finding_count,
            "original_message": self.original_message,
            "normalised_message": self.normalised_message,
            "findings": [item.to_dict() for item in self.findings],
            "checks_performed": list(self.checks_performed),
            "checks_incomplete": list(self.checks_incomplete),
            "limitations": list(self.limitations),
            "risk_policy": self.risk_policy,
            "notes": list(self.notes),
        }
