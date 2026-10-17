"""Compiled, named deterministic text rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from scamsentry.models import (
    Category,
    EvidenceSource,
    Finding,
    FindingSource,
    ObservationKind,
    Severity,
)
from scamsentry.normalizer import locate_in_original


@dataclass(frozen=True)
class TextRule:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    explanation: str
    pattern: Pattern[str]
    observation_kind: ObservationKind = ObservationKind.HEURISTIC


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


TEXT_RULES: tuple[TextRule, ...] = (
    TextRule(
        rule_id="A_ACCOUNT_LOCK",
        category=Category.URGENCY,
        severity=Severity.HIGH,
        title="Account blocking or suspension language",
        explanation=(
            "The text claims an account will be or has been blocked, suspended, "
            "locked, or closed. This is a common pressure tactic, not proof of a scam."
        ),
        pattern=_compile(
            r"\b(?:your\s+)?account\s+(?:will\s+be\s+|has\s+been\s+|is\s+(?:being\s+)?)?"
            r"(?:blocked|suspended|closed|locked|terminated|disabled|restricted)\b|"
            r"\b(?:suspend|suspended|block|blocked|lock|locked|restrict|restricted|close|closed)\s+(?:your\s+)?account\b"
        ),
    ),
    TextRule(
        rule_id="A_LOSS_OF_ACCESS",
        category=Category.URGENCY,
        severity=Severity.HIGH,
        title="Threatened loss of access",
        explanation=(
            "The text threatens loss of access unless the reader acts. "
            "Treat as an observed pressure cue, not a verified incident."
        ),
        pattern=_compile(
            r"\b(?:lose|losing|loss\s+of)\s+(?:all\s+)?(?:access|your\s+account)\b|"
            r"\bunless\s+you\s+(?:verify|confirm|update|pay|respond|act)\b"
        ),
    ),
    TextRule(
        rule_id="A_URGENT_DEADLINE",
        category=Category.URGENCY,
        severity=Severity.MEDIUM,
        title="Urgent deadline or immediate action",
        explanation=(
            "Urgent-action phrasing or a short deadline was observed. "
            "Legitimate notices can use similar language."
        ),
        pattern=_compile(
            r"(?<!\bno\s)urgent(?:ly)?\s+(?:action|attention|response|verification)\s+required\b|"
            r"\b(?:act|respond|verify|confirm)\s+now\b|"
            r"\bfinal\s+(?:notice|warning)\b|"
            r"\bwithin\s+\d+\s+(?:hour|hours|minute|minutes|hr|hrs|mins?)\b|"
            r"\bimmediately\s+(?:verify|confirm|update|pay|act|respond)\b|"
            r"\b(?:verify|confirm|update|pay|act|respond)\s+immediately\b"
        ),
    ),
    TextRule(
        rule_id="B_PASSWORD_REQUEST",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        title="Password or credential request",
        explanation=(
            "The text asks the reader to enter, confirm, or send a password. "
            "Legitimate services rarely request passwords over email or chat."
        ),
        pattern=_compile(
            r"\b(?:enter|confirm|provide|send|share|type|update|verify)\s+"
            r"(?:your\s+)?(?:password|passcode|pin|security\s+code)\b"
        ),
    ),
    TextRule(
        rule_id="B_OTP",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        title="OTP or verification-code request",
        explanation=(
            "A one-time password, OTP, or verification code is requested. "
            "This is an observed sensitive-data request, not proof of compromise."
        ),
        pattern=_compile(
            r"\b(?:one[-\s]?time\s+(?:pass(?:word|code)|code)|otp|"
            r"verification\s+code|2fa\s+code|authenticator\s+code)\b"
        ),
    ),
    TextRule(
        rule_id="B_BANKING_DETAILS",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        title="Banking or payment-detail request",
        explanation=(
            "The text asks for banking or payment details (card, CVV, IBAN, etc.)."
        ),
        pattern=_compile(
            r"\b(?:credit\s+card|debit\s+card|card\s+number|cvv|cvc|routing\s+number|iban|sort\s+code|"
            r"bank\s+account(?:\s+number)?|banking\s+details|payment\s+details)\b"
        ),
    ),
    TextRule(
        rule_id="C_UNEXPECTED_FEE",
        category=Category.PAYMENT,
        severity=Severity.HIGH,
        title="Unexpected fee language",
        explanation=(
            "The text mentions an unexpected, processing, or release fee. "
            "Fees can be legitimate; the cue is the unexpected-payment framing."
        ),
        pattern=_compile(
            r"\b(?:unexpected|additional|processing|release|clearance|customs)\s+fee\b"
        ),
    ),
    TextRule(
        rule_id="C_IMMEDIATE_PAYMENT",
        category=Category.PAYMENT,
        severity=Severity.HIGH,
        title="Immediate payment demand",
        explanation="The text demands payment now or immediately.",
        pattern=_compile(
            r"\b(?:immediate(?:ly)?\s+payment|payment\s+(?:is\s+)?(?:required\s+)?immediately|"
            r"pay\s+(?:now|immediately|today)|wire\s+transfer|gift\s+cards?\s+(?:to|required|as\s+payment))\b"
        ),
    ),
    TextRule(
        rule_id="C_PRIZE_REWARD",
        category=Category.PAYMENT,
        severity=Severity.MEDIUM,
        title="Prize, refund, or reward claim",
        explanation=(
            "Unexpected prize, lottery, refund, or reward language was observed. "
            "This is a heuristic, not confirmation of fraud."
        ),
        pattern=_compile(
            r"\b(?:congratulations,?\s+you(?:'ve|\s+have)?\s+won|you\s+have\s+won|claim\s+your\s+(?:prize|reward|refund)|"
            r"lottery\s+winner|refund\s+(?:pending|waiting|ready)|"
            r"selected\s+as\s+a\s+winner)\b"
        ),
    ),
    TextRule(
        rule_id="D_ORG_CLAIM",
        category=Category.IMPERSONATION,
        severity=Severity.MEDIUM,
        title="Claim to represent an organisation",
        explanation=(
            "The text claims to represent a bank, delivery service, employer, "
            "government, or online service. Brand mention alone is not scored as "
            "impersonation unless combined with a suspicious request or pressure."
        ),
        pattern=_compile(
            r"\b(?:this\s+is|we\s+are(?:\s+calling)?(?:\s+from)?|from)\s+(?:the\s+)?"
            r"(?:irs|hmrc|government|social\s+security|federal\s+(?:reserve|bureau)|your\s+"
            r"(?:bank|employer|delivery\s+service)|paypal|amazon|apple|microsoft|"
            r"google|dhl|fedex|ups)\b|"
            r"\b(?:paypal|amazon|apple(?:\s+id)?|microsoft|google|netflix|dhl|"
            r"fedex|ups|hmrc|irs|social\s+security)\s+(?:security|support|account\s+team|delivery|"
            r"fraud\s+department)\b"
        ),
    ),
)

PRESSURE_CATEGORIES = frozenset(
    {Category.URGENCY, Category.CREDENTIAL, Category.PAYMENT}
)


def _span_from_match(
    original: str,
    normalised: str,
    match: re.Match[str],
    haystack: str,
    index_map: tuple[int, ...] = (),
) -> tuple[str, EvidenceSource, int | None, int | None]:
    snippet = match.group(0)
    if haystack is original:
        return snippet, EvidenceSource.ORIGINAL, match.start(), match.end()

    # When matching normalised text, use exact index_map if available
    s = match.start()
    e = match.end()
    if index_map and 0 <= s < len(index_map) and 0 < e <= len(index_map) and s < e:
        orig_start = index_map[s]
        orig_end = index_map[e - 1] + 1
        if 0 <= orig_start < orig_end <= len(original):
            return original[orig_start:orig_end], EvidenceSource.ORIGINAL, orig_start, orig_end

    # Fallback: exact unique occurrence only
    located = locate_in_original(original, snippet)
    if located is not None:
        start, end = located
        return original[start:end], EvidenceSource.ORIGINAL, start, end

    # If the exact occurrence cannot be mapped reliably, leave offsets unset
    return snippet, EvidenceSource.NORMALISED, None, None


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def dedupe_same_rule(findings: list[Finding]) -> list[Finding]:
    """Drop overlapping findings that share a rule_id, keeping the longer span."""

    by_rule: dict[str, list[Finding]] = {}
    leftover: list[Finding] = []
    for finding in findings:
        if finding.start_offset is None or finding.end_offset is None:
            leftover.append(finding)
            continue
        by_rule.setdefault(finding.rule_id, []).append(finding)

    kept: list[Finding] = list(leftover)
    for group in by_rule.values():
        group.sort(key=lambda item: (item.start_offset or 0, -(item.end_offset or 0)))
        accepted: list[Finding] = []
        for candidate in group:
            clash = False
            for existing in accepted:
                if _overlaps(
                    candidate.start_offset or 0,
                    candidate.end_offset or 0,
                    existing.start_offset or 0,
                    existing.end_offset or 0,
                ):
                    clash = True
                    break
            if not clash:
                accepted.append(candidate)
        kept.extend(accepted)
    return kept


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings so overlapping or duplicate observations are not double-counted.

    1. Within the same rule, overlapping spans collapse to the longer span.
    2. Across different rules, identical spans retain the finding with higher severity.
    """
    same_rule_deduped = dedupe_same_rule(findings)
    rank = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3}
    by_span: dict[tuple[int, int], Finding] = {}
    result: list[Finding] = []
    for item in same_rule_deduped:
        if item.start_offset is None or item.end_offset is None:
            result.append(item)
            continue
        span = (item.start_offset, item.end_offset)
        existing = by_span.get(span)
        if existing is None or rank[item.severity] > rank[existing.severity]:
            by_span[span] = item
    result.extend(by_span.values())
    return result


def run_text_rules(
    original: str,
    normalised: str,
    index_map: tuple[int, ...] = (),
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in TEXT_RULES:
        for match in rule.pattern.finditer(original):
            evidence, source, start, end = _span_from_match(
                original, normalised, match, original, index_map
            )
            findings.append(
                Finding(
                    id="",
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    evidence_text=evidence,
                    evidence_source=source,
                    explanation=rule.explanation,
                    observation_kind=rule.observation_kind,
                    source=FindingSource.DETERMINISTIC,
                    start_offset=start,
                    end_offset=end,
                )
            )
        for match in rule.pattern.finditer(normalised):
            evidence, source, start, end = _span_from_match(
                original, normalised, match, normalised, index_map
            )
            findings.append(
                Finding(
                    id="",
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    evidence_text=evidence,
                    evidence_source=source,
                    explanation=rule.explanation,
                    observation_kind=rule.observation_kind,
                    source=FindingSource.DETERMINISTIC,
                    start_offset=start,
                    end_offset=end,
                )
            )
    return dedupe_findings(findings)


def apply_impersonation_gate(findings: list[Finding]) -> list[Finding]:
    """Keep D_ORG_CLAIM only when combined with pressure or a sensitive request."""

    has_pressure = any(item.category in PRESSURE_CATEGORIES for item in findings)
    gated: list[Finding] = []
    for item in findings:
        if item.rule_id != "D_ORG_CLAIM":
            gated.append(item)
            continue
        if has_pressure:
            gated.append(
                Finding(
                    id=item.id,
                    rule_id="D_IMPERSONATION",
                    category=Category.IMPERSONATION,
                    severity=Severity.HIGH,
                    title="Possible impersonation combined with a suspicious request",
                    evidence_text=item.evidence_text,
                    evidence_source=item.evidence_source,
                    explanation=(
                        "An organisation claim appears together with urgency, a "
                        "credential request, or a payment demand. Brand mention "
                        "alone is not treated as impersonation. This remains a "
                        "heuristic, not proof."
                    ),
                    observation_kind=ObservationKind.HEURISTIC,
                    source=item.source,
                    start_offset=item.start_offset,
                    end_offset=item.end_offset,
                )
            )
        # else: drop brand-only mention
    return gated
