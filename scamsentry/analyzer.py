"""Public Stage 1 analysis API. No LLM imports."""

from __future__ import annotations

from pathlib import Path

from scamsentry.models import (
    AnalysisResult,
    AnalysisStatus,
    Category,
    DEFAULT_MAX_BYTES,
    EvidenceSource,
    Finding,
    FindingSource,
    InputError,
    ObservationKind,
    RiskBand,
    STANDARD_LIMITATIONS,
    Severity,
)
from scamsentry.normalizer import normalise_message, validate_message
from scamsentry.rules import apply_impersonation_gate, run_text_rules
from scamsentry.url_checks import extract_urls, findings_for_url


CHECKS_PERFORMED: tuple[str, ...] = (
    "input_validation",
    "unicode_normalisation",
    "invisible_formatting",
    "url_extraction",
    "url_structure",
    "text_rules",
    "impersonation_gate",
    "risk_policy",
)

CHECKS_INCOMPLETE: tuple[str, ...] = (
    "dns_resolution",
    "http_fetch",
    "redirect_follow",
    "javascript_execution",
    "reputation_lookup",
    "model_analysis",
)


def _formatting_findings(original: str, spans: tuple) -> list[Finding]:
    if not spans:
        return []
    first = spans[0]
    codes = sorted({span.codepoint for span in spans})
    sample = original[first.start : first.end]
    return [
        Finding(
            id="",
            rule_id="F_INVISIBLE_UNICODE",
            category=Category.FORMATTING,
            severity=Severity.MEDIUM,
            title="Invisible or formatting Unicode present",
            evidence_text=sample,
            evidence_source=EvidenceSource.ORIGINAL,
            explanation=(
                f"{len(spans)} invisible/formatting code point(s) observed "
                f"({', '.join(codes[:8])}"
                f"{', …' if len(codes) > 8 else ''}). "
                "The original text is preserved; matching uses a separate "
                "normalised form and does not treat the altered text as trustworthy."
            ),
            observation_kind=ObservationKind.DIRECT,
            source=FindingSource.DETERMINISTIC,
            start_offset=first.start,
            end_offset=first.end,
        )
    ]


def _assign_ids(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(
        findings,
        key=lambda item: (
            item.rule_id,
            item.start_offset if item.start_offset is not None else 10**9,
            item.evidence_text,
        ),
    )
    numbered: list[Finding] = []
    for index, item in enumerate(ordered, start=1):
        numbered.append(
            Finding(
                id=f"F{index:03d}",
                rule_id=item.rule_id,
                category=item.category,
                severity=item.severity,
                title=item.title,
                evidence_text=item.evidence_text,
                evidence_source=item.evidence_source,
                explanation=item.explanation,
                observation_kind=item.observation_kind,
                source=item.source,
                start_offset=item.start_offset,
                end_offset=item.end_offset,
            )
        )
    return numbered


def assign_risk_band(
    findings: list[Finding],
    status: AnalysisStatus = AnalysisStatus.COMPLETE,
) -> RiskBand:
    """Assign a heuristic triage band (not calibrated probability or proof of fraud).

    Risk bands:
    - LOW_CONCERN: Zero findings detected across all rules and URL checks.
    - REVIEW: One or more indicators present, but insufficient independent vectors
      for high concern. Correlated indicators (e.g. brand impersonation derived
      solely from urgency) and duplicate findings within the same category remain REVIEW.
    - HIGH_CONCERN: Two or more genuinely independent categories with at least one
      HIGH severity finding (e.g. Urgency + Credential harvesting, or Urgency +
      Suspicious URL, or Credential + Suspicious URL).
    - INCONCLUSIVE: Analysis failed or is partial/incomplete.
    """
    if status in {AnalysisStatus.FAILED, AnalysisStatus.PARTIAL}:
        return RiskBand.INCONCLUSIVE

    if not findings:
        return RiskBand.LOW_CONCERN

    independent: dict[Category, Severity] = {}
    rank = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
    for item in findings:
        current = independent.get(item.category)
        if current is None or rank[item.severity] > rank[current]:
            independent[item.category] = item.severity

    strong_categories = {
        category
        for category, severity in independent.items()
        if severity in {Severity.MEDIUM, Severity.HIGH}
    }
    has_high = any(severity is Severity.HIGH for severity in independent.values())

    # Correlated indicators: Impersonation rule is triggered by pressure (urgency).
    # If the ONLY strong categories present are {IMPERSONATION, URGENCY}, they are
    # correlated signals from the same textual pattern and do not represent two
    # independent attack vectors.
    if strong_categories == {Category.IMPERSONATION, Category.URGENCY}:
        return RiskBand.REVIEW

    if len(strong_categories) >= 2 and has_high:
        return RiskBand.HIGH_CONCERN
    return RiskBand.REVIEW


def analyse_message(
    message: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> AnalysisResult:
    """Analyse untrusted message text. Never contacts the network or an LLM."""

    validate_message(message, max_bytes=max_bytes)
    normalisation = normalise_message(message)

    findings: list[Finding] = []
    findings.extend(_formatting_findings(message, normalisation.invisible_spans))

    extracted_urls = extract_urls(message)
    for extracted in extracted_urls:
        findings.extend(findings_for_url(extracted))

    findings.extend(
        run_text_rules(message, normalisation.normalised, normalisation.index_map)
    )
    findings = apply_impersonation_gate(findings)
    findings = _assign_ids(findings)

    notes = (
        "Stage 1 is deterministic and provider-independent.",
        "A finding is an indicator for human review, not conclusive proof of a scam.",
        "LOW_CONCERN means no implemented check fired; it is not a verified-safe verdict.",
    )
    if extracted_urls:
        notes = notes + (
            "Embedded URLs were parsed locally only; destinations were not fetched.",
        )

    return AnalysisResult(
        original_message=message,
        normalised_message=normalisation.normalised,
        findings=findings,
        analysis_status=AnalysisStatus.COMPLETE,
        risk_band=assign_risk_band(findings),
        checks_performed=CHECKS_PERFORMED,
        checks_incomplete=CHECKS_INCOMPLETE,
        limitations=STANDARD_LIMITATIONS,
        notes=notes,
    )


def analyse_file(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> AnalysisResult:
    file_path = Path(path)
    if file_path.is_dir():
        raise InputError(f"Path is a directory, not a file: {file_path}")
    try:
        size = file_path.stat().st_size
    except FileNotFoundError as exc:
        raise InputError(f"File not found: {file_path}") from exc
    except IsADirectoryError as exc:
        raise InputError(f"Path is a directory, not a file: {file_path}") from exc
    except OSError as exc:
        raise InputError(f"Unable to read file {file_path}: {exc.strerror or exc}") from exc

    if size > max_bytes:
        raise InputError(
            f"File exceeds the configured maximum of {max_bytes} UTF-8 bytes "
            f"(file size {size})."
        )
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise InputError(f"Unable to read file {file_path}: {exc.strerror or exc}") from exc
    if len(data) > max_bytes:
        raise InputError(
            f"File exceeds the configured maximum of {max_bytes} UTF-8 bytes "
            f"(received {len(data)})."
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(
            "File is not valid UTF-8. Malformed Unicode is rejected rather than silently repaired."
        ) from exc
    return analyse_message(text, max_bytes=max_bytes)
