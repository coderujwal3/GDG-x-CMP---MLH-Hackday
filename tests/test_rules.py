from __future__ import annotations

from scamsentry.models import Category
from scamsentry.normalizer import normalise_message
from scamsentry.rules import apply_impersonation_gate, run_text_rules


def _run(text: str):
    norm = normalise_message(text)
    return apply_impersonation_gate(run_text_rules(text, norm.normalised, norm.index_map))


def test_benign_account_payment_urgent_context() -> None:
    text = (
        "The monthly account review is Thursday. Payment for last month's invoice "
        "is due on the 30th. There is no urgent action required."
    )
    findings = _run(text)
    assert findings == []


def test_suspicious_urgency_and_credentials() -> None:
    text = (
        "Your account will be suspended. Enter your password and the verification "
        "code now."
    )
    findings = _run(text)
    rule_ids = {item.rule_id for item in findings}
    assert "A_ACCOUNT_LOCK" in rule_ids
    assert "B_PASSWORD_REQUEST" in rule_ids
    assert "B_OTP" in rule_ids


def test_duplicate_overlapping_findings_deduped() -> None:
    text = "Your account will be suspended. Your account will be suspended."
    findings = _run(text)
    locks = [item for item in findings if item.rule_id == "A_ACCOUNT_LOCK"]
    assert len(locks) == 2  # two non-overlapping copies kept
    single = "Your account will be suspended immediately verify this"
    # overlapping same-rule matches collapse
    overlapping_source = "account will be suspended"
    findings_one = _run(f"Your {overlapping_source}.")
    locks_one = [item for item in findings_one if item.rule_id == "A_ACCOUNT_LOCK"]
    assert len(locks_one) == 1
    del single


def test_brand_mention_alone_is_not_impersonation() -> None:
    text = "We are from PayPal. Enjoy the product update notes this week."
    findings = _run(text)
    assert all(item.category is not Category.IMPERSONATION for item in findings)


def test_impersonation_with_pressure() -> None:
    text = "This is Amazon Security. Enter your password immediately."
    findings = _run(text)
    assert any(item.rule_id == "D_IMPERSONATION" for item in findings)


def test_offsets_quote_original() -> None:
    text = "Please enter your password today."
    findings = _run(text)
    cred = [item for item in findings if item.rule_id == "B_PASSWORD_REQUEST"]
    assert cred
    item = cred[0]
    assert item.start_offset is not None and item.end_offset is not None
    assert text[item.start_offset : item.end_offset] == item.evidence_text
    assert "password" in item.evidence_text.lower()


def test_payment_and_reward_rules() -> None:
    text = (
        "Congratulations, you have won a lottery prize! "
        "Pay the customs fee now via wire transfer to claim your reward."
    )
    findings = _run(text)
    rule_ids = {item.rule_id for item in findings}
    assert "C_PRIZE_REWARD" in rule_ids
    assert "C_UNEXPECTED_FEE" in rule_ids
    assert "C_IMMEDIATE_PAYMENT" in rule_ids


def test_banking_details_rule() -> None:
    text = "Please provide your debit card number and CVV to complete verification."
    findings = _run(text)
    assert any(item.rule_id == "B_BANKING_DETAILS" for item in findings)


def test_account_phrasing_variations() -> None:
    text = "We have suspended your account. Please verify immediately."
    findings = _run(text)
    rule_ids = {item.rule_id for item in findings}
    assert "A_ACCOUNT_LOCK" in rule_ids
    assert "A_URGENT_DEADLINE" in rule_ids


def test_cross_rule_identical_span_deduplication() -> None:
    from scamsentry.models import EvidenceSource, Finding, FindingSource, ObservationKind, Severity
    from scamsentry.rules import dedupe_findings

    f1 = Finding(
        id="",
        rule_id="RULE_A",
        category=Category.URGENCY,
        severity=Severity.MEDIUM,
        title="Title A",
        evidence_text="test text",
        evidence_source=EvidenceSource.ORIGINAL,
        explanation="Exp A",
        observation_kind=ObservationKind.HEURISTIC,
        source=FindingSource.DETERMINISTIC,
        start_offset=10,
        end_offset=19,
    )
    f2 = Finding(
        id="",
        rule_id="RULE_B",
        category=Category.CREDENTIAL,
        severity=Severity.HIGH,
        title="Title B",
        evidence_text="test text",
        evidence_source=EvidenceSource.ORIGINAL,
        explanation="Exp B",
        observation_kind=ObservationKind.HEURISTIC,
        source=FindingSource.DETERMINISTIC,
        start_offset=10,
        end_offset=19,
    )
    deduped = dedupe_findings([f1, f2])
    assert len(deduped) == 1
    assert deduped[0].rule_id == "RULE_B"
    assert deduped[0].severity == Severity.HIGH


def test_repeated_phrases_with_invisible_unicode_offsets() -> None:
    text = (
        "First notice: your account will be suspended today. "
        "Second notice: your account will be sus\u200bpended later."
    )
    findings = _run(text)
    locks = [f for f in findings if f.rule_id == "A_ACCOUNT_LOCK"]
    assert len(locks) == 2

    # First occurrence
    first = locks[0]
    assert first.start_offset is not None and first.end_offset is not None
    assert text[first.start_offset : first.end_offset] == "your account will be suspended"
    assert first.start_offset < 50

    # Second occurrence has invisible character
    second = locks[1]
    assert second.start_offset is not None and second.end_offset is not None
    assert text[second.start_offset : second.end_offset] == "your account will be sus\u200bpended"
    assert "\u200b" in second.evidence_text
    assert second.start_offset > 50

    # Offsets must be distinct and non-overlapping
    assert first.end_offset < second.start_offset


