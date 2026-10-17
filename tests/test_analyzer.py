from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from scamsentry import analyse_message
from scamsentry.analyzer import analyse_file, assign_risk_band
from scamsentry.models import (
    AnalysisStatus,
    Category,
    Finding,
    FindingSource,
    InputError,
    ObservationKind,
    RiskBand,
    Severity,
    EvidenceSource,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_size_limit_before_analysis() -> None:
    with pytest.raises(InputError, match="exceeds"):
        analyse_message("hello world", max_bytes=3)


def test_unicode_invisible_flagged_and_original_kept() -> None:
    original = "Please enter your password\u200b now."
    result = analyse_message(original)
    assert result.original_message == original
    assert any(item.rule_id == "F_INVISIBLE_UNICODE" for item in result.findings)
    assert "\u200b" in result.original_message


def test_fictional_suspicious_high_concern() -> None:
    text = EXAMPLES.joinpath("suspicious_message.txt").read_text(encoding="utf-8")
    result = analyse_message(text)
    assert result.analysis_status is AnalysisStatus.COMPLETE
    categories = {item.category for item in result.findings}
    assert Category.URGENCY in categories
    assert Category.CREDENTIAL in categories
    assert Category.URL in categories
    assert result.risk_band is RiskBand.HIGH_CONCERN
    assert any(item.rule_id == "E_IP_HOST" for item in result.findings)
    assert any(item.rule_id == "E_UNUSUAL_PORT" for item in result.findings)
    assert any(item.rule_id == "E_MISLEADING_HOST" for item in result.findings)
    ip_findings = [
        item
        for item in result.findings
        if item.rule_id == "E_HOST_STRUCTURE" and "192.0.2.55" in item.evidence_text
    ]
    assert ip_findings == []


def test_benign_low_concern() -> None:
    text = EXAMPLES.joinpath("benign_message.txt").read_text(encoding="utf-8")
    result = analyse_message(text)
    assert result.risk_band is RiskBand.LOW_CONCERN
    assert result.finding_count == 0


def test_ambiguous_not_high_concern() -> None:
    text = EXAMPLES.joinpath("ambiguous_message.txt").read_text(encoding="utf-8")
    result = analyse_message(text)
    assert result.risk_band in {RiskBand.LOW_CONCERN, RiskBand.REVIEW}
    assert result.risk_band is not RiskBand.HIGH_CONCERN


def test_repeated_same_rule_does_not_auto_inflate() -> None:
    text = "Your account will be suspended. " * 8
    result = analyse_message(text)
    assert result.risk_band is RiskBand.REVIEW
    locks = [item for item in result.findings if item.rule_id == "A_ACCOUNT_LOCK"]
    assert len(locks) >= 2


def test_accurate_quotes_and_offsets() -> None:
    text = "Enter your password at once."
    result = analyse_message(text)
    for item in result.findings:
        if item.start_offset is None:
            continue
        quoted = text[item.start_offset : item.end_offset]
        assert quoted == item.evidence_text


def test_json_serialisation_deterministic() -> None:
    text = "Your account will be suspended. Enter your password."
    first = json.dumps(analyse_message(text).to_dict(), ensure_ascii=False)
    second = json.dumps(analyse_message(text).to_dict(), ensure_ascii=False)
    assert first == second
    payload = json.loads(first)
    assert payload["schema_version"] == "1.0"
    assert payload["findings"][0]["source"] == "deterministic"
    assert "original_message" in payload


def test_risk_band_policy_unit() -> None:
    def finding(category: Category, severity: Severity, rule_id: str) -> Finding:
        return Finding(
            id="x",
            rule_id=rule_id,
            category=category,
            severity=severity,
            title="t",
            evidence_text="e",
            evidence_source=EvidenceSource.ORIGINAL,
            explanation="x",
            observation_kind=ObservationKind.HEURISTIC,
            source=FindingSource.DETERMINISTIC,
        )

    assert assign_risk_band([]) is RiskBand.LOW_CONCERN
    one = [finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK")]
    assert assign_risk_band(one) is RiskBand.REVIEW
    two = one + [finding(Category.CREDENTIAL, Severity.HIGH, "B_OTP")]
    assert assign_risk_band(two) is RiskBand.HIGH_CONCERN


def test_correlated_indicators_do_not_inflate_risk_band() -> None:
    def finding(category: Category, severity: Severity, rule_id: str) -> Finding:
        return Finding(
            id="x",
            rule_id=rule_id,
            category=category,
            severity=severity,
            title="t",
            evidence_text="e",
            evidence_source=EvidenceSource.ORIGINAL,
            explanation="x",
            observation_kind=ObservationKind.HEURISTIC,
            source=FindingSource.DETERMINISTIC,
        )

    # Correlated pair: Impersonation derived solely from Urgency
    correlated = [
        finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK"),
        finding(Category.IMPERSONATION, Severity.MEDIUM, "D_IMPERSONATION"),
    ]
    assert assign_risk_band(correlated) is RiskBand.REVIEW

    # Real message where only Amazon + account suspended are mentioned (no password/payment/URL)
    message = "This is Amazon Security. Your account will be suspended."
    res = analyse_message(message)
    categories = {f.category for f in res.findings}
    assert categories == {Category.URGENCY, Category.IMPERSONATION}
    assert res.risk_band is RiskBand.REVIEW


def test_duplicate_and_same_category_findings_cannot_inflate_risk_band() -> None:
    def finding(category: Category, severity: Severity, rule_id: str) -> Finding:
        return Finding(
            id="x",
            rule_id=rule_id,
            category=category,
            severity=severity,
            title="t",
            evidence_text="e",
            evidence_source=EvidenceSource.ORIGINAL,
            explanation="x",
            observation_kind=ObservationKind.HEURISTIC,
            source=FindingSource.DETERMINISTIC,
        )

    # 10 duplicate findings of the same high-severity rule
    duplicates = [
        finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK")
        for _ in range(10)
    ]
    assert assign_risk_band(duplicates) is RiskBand.REVIEW

    # Multiple distinct findings within the same category
    same_category = [
        finding(Category.URL, Severity.HIGH, "E_IP_HOST"),
        finding(Category.URL, Severity.MEDIUM, "E_UNUSUAL_PORT"),
        finding(Category.URL, Severity.LOW, "E_DEFANGED_URL"),
    ]
    assert assign_risk_band(same_category) is RiskBand.REVIEW

    # Multiple LOW severity findings across 3 categories do not jump to HIGH_CONCERN
    low_findings = [
        finding(Category.URGENCY, Severity.LOW, "A_LOW"),
        finding(Category.URL, Severity.LOW, "E_LOW"),
        finding(Category.FORMATTING, Severity.LOW, "F_LOW"),
    ]
    assert assign_risk_band(low_findings) is RiskBand.REVIEW


def test_independent_categories_with_high_severity_reach_high_concern() -> None:
    def finding(category: Category, severity: Severity, rule_id: str) -> Finding:
        return Finding(
            id="x",
            rule_id=rule_id,
            category=category,
            severity=severity,
            title="t",
            evidence_text="e",
            evidence_source=EvidenceSource.ORIGINAL,
            explanation="x",
            observation_kind=ObservationKind.HEURISTIC,
            source=FindingSource.DETERMINISTIC,
        )

    # Independent: Urgency (HIGH) + Credential (HIGH)
    combo1 = [
        finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK"),
        finding(Category.CREDENTIAL, Severity.HIGH, "B_PASSWORD"),
    ]
    assert assign_risk_band(combo1) is RiskBand.HIGH_CONCERN

    # Independent: Urgency (HIGH) + URL (MEDIUM)
    combo2 = [
        finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK"),
        finding(Category.URL, Severity.MEDIUM, "E_UNUSUAL_PORT"),
    ]
    assert assign_risk_band(combo2) is RiskBand.HIGH_CONCERN

    # Correlated Impersonation + Urgency + Independent URL vector
    combo3 = [
        finding(Category.IMPERSONATION, Severity.MEDIUM, "D_IMPERSONATION"),
        finding(Category.URGENCY, Severity.HIGH, "A_ACCOUNT_LOCK"),
        finding(Category.URL, Severity.MEDIUM, "E_IP_HOST"),
    ]
    assert assign_risk_band(combo3) is RiskBand.HIGH_CONCERN


def test_model_independent_no_llm_imports() -> None:
    root = ROOT / "scamsentry"
    forbidden = ("openai", "anthropic", "transformers", "llama", "gemini", "httpx", "requests")
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                assert name not in forbidden
                assert name != "urllib.request"


def test_analyse_file_and_invalid_unicode(tmp_path: Path) -> None:
    path = tmp_path / "ok.txt"
    path.write_text("Hello example.com is not a URL without a scheme.", encoding="utf-8")
    result = analyse_file(path)
    assert result.analysis_status is AnalysisStatus.COMPLETE

    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(InputError, match="UTF-8"):
        analyse_file(bad)

    with pytest.raises(InputError, match="not found"):
        analyse_file(tmp_path / "missing.txt")


def test_risk_band_inconclusive_on_failed_or_partial() -> None:
    assert assign_risk_band([], status=AnalysisStatus.FAILED) is RiskBand.INCONCLUSIVE
    assert assign_risk_band([], status=AnalysisStatus.PARTIAL) is RiskBand.INCONCLUSIVE


def test_analyse_file_errors(tmp_path: Path) -> None:
    # Directory as file
    sub_dir = tmp_path / "sub_dir"
    sub_dir.mkdir()
    with pytest.raises(InputError, match="directory"):
        analyse_file(sub_dir)

    # Oversized file
    big_file = tmp_path / "big.txt"
    big_file.write_text("A" * 100, encoding="utf-8")
    with pytest.raises(InputError, match="exceeds"):
        analyse_file(big_file, max_bytes=50)


def test_analyse_message_type_validation() -> None:
    with pytest.raises(InputError, match="string"):
        analyse_message(12345)  # type: ignore[arg-type]


def test_analyse_file_with_spaces_and_non_ascii_paths(tmp_path: Path) -> None:
    folder = tmp_path / "cas d'analyse 2026" / "dossier_sécurité"
    folder.mkdir(parents=True)
    file_path = folder / "alerte_bancaire_#1.txt"
    file_path.write_text(
        "This is Amazon Security. Enter your password immediately: https://example.com/login",
        encoding="utf-8",
    )
    result = analyse_file(file_path)
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert result.risk_band is RiskBand.HIGH_CONCERN
    assert result.finding_count >= 2


def test_crlf_message_analysis() -> None:
    windows_crlf_text = (
        "This is Amazon Security.\r\n"
        "Your account will be suspended within 24 hours unless you verify.\r\n"
        "Enter your password now: http://192.0.2.1/login\r\n"
    )
    result = analyse_message(windows_crlf_text)
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert result.risk_band is RiskBand.HIGH_CONCERN
    # Offsets quote exact slices of windows_crlf_text
    for finding in result.findings:
        if finding.start_offset is not None and finding.end_offset is not None:
            assert windows_crlf_text[finding.start_offset : finding.end_offset] == finding.evidence_text


def test_stability_across_repeated_runs() -> None:
    text = (
        "This is PayPal support. Your account has been locked. "
        "Verify your password at once: http://192.0.2.1/verify"
    )
    reference = analyse_message(text).to_dict()
    for _ in range(10):
        run_result = analyse_message(text).to_dict()
        assert run_result == reference


