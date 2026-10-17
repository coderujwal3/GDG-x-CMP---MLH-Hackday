"""Command-line interface. Diagnostics on stderr; JSON on stdout."""

from __future__ import annotations

import argparse
import json
import math
import sys
import textwrap
from typing import Sequence, TextIO

from scamsentry.analyzer import analyse_file, analyse_message
from scamsentry.models import AnalysisResult, InputError, ScamSentryError


EVIDENCE_TRUNCATE = 80


class ArgumentError(ScamSentryError):
    """CLI usage error."""


class QuietParser(argparse.ArgumentParser):
    """Raise instead of exiting so callers can keep JSON on stdout."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise ArgumentError(message)


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number of seconds") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number of seconds")
    return timeout


def _build_parser() -> QuietParser:
    parser = QuietParser(
        prog="scamsentry",
        description=(
            "ScamSentry: deterministic offline message triage, with optional local "
            "AI interpretation and deterministic recommendations. Findings are "
            "indicators, not proof of a scam."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser(
        "analyze",
        help="Analyse a message from --text or --file",
    )
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Message text to analyse")
    source.add_argument("--file", help="UTF-8 file containing the message")
    analyze.add_argument(
        "--json",
        action="store_true",
        help="Write the full AnalysisResult JSON to stdout",
    )
    analyze.add_argument(
        "--include-message",
        action="store_true",
        help="Include the original message in human-readable output (off by default)",
    )
    analyze.add_argument(
        "--max-bytes",
        type=int,
        default=50 * 1024,
        help="Maximum UTF-8 size in bytes (default: 51200)",
    )
    analyze.add_argument(
        "--ai",
        action="store_true",
        help="Add optional local-model interpretation and deterministic Stage 3 decision",
    )
    analyze.add_argument(
        "--decision",
        action="store_true",
        help="Add deterministic Stage 3 risk assessment and recommendations",
    )
    analyze.add_argument(
        "--ai-model",
        default="gemma3:4b",
        help="Ollama model already installed locally (default: gemma3:4b)",
    )
    analyze.add_argument(
        "--ai-timeout",
        type=_positive_timeout,
        default=120.0,
        metavar="SECONDS",
        help="Maximum time for each Ollama CLI operation (default: 120)",
    )
    return parser


def _truncate(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _wrapped_line(label: str, value: str, *, indent: str = "  ") -> list[str]:
    prefix = f"{indent}{label}: "
    return textwrap.wrap(
        prefix + value,
        width=88,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [prefix.rstrip()]


def _wrapped_bullet(value: str, *, indent: str = "    ") -> list[str]:
    prefix = f"{indent}- "
    return textwrap.wrap(
        prefix + value,
        width=88,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    ) or [prefix.rstrip()]


def _render_human(result: AnalysisResult, *, include_message: bool) -> str:
    lines: list[str] = [
        "SCAMSENTRY ANALYSIS REPORT",
        "==========================",
        "",
        "1. Stage 1 deterministic analysis",
        f"  Status: {result.analysis_status.value}",
        f"  Stage 1 risk band: "
        f"{result.risk_band.value if result.risk_band else 'n/a'} "
        "(rule-based, not a probability)",
        f"  Findings: {result.finding_count}",
        "",
    ]
    if include_message:
        lines.extend(_wrapped_line("Original message", result.original_message))
        lines.append("")
    else:
        lines.extend(
            _wrapped_line(
                "Original message omitted",
                "pass --include-message to show it (may contain sensitive text)",
            )
        )
        lines.append("")

    if not result.findings:
        lines.append("  No implemented checks fired; this is not a verified-safe verdict.")
    else:
        lines.append("  Findings:")
    for finding in result.findings:
        offset = ""
        if finding.start_offset is not None and finding.end_offset is not None:
            offset = f" [{finding.start_offset}:{finding.end_offset}]"
        lines.append(
            f"    [{finding.id}] {finding.rule_id} — {finding.severity.value} "
            f"/ {finding.category.value} ({finding.observation_kind.value})"
        )
        lines.extend(_wrapped_line("Observation", finding.title, indent="      "))
        lines.extend(
            _wrapped_line(
                f"Evidence{offset}",
                repr(_truncate(finding.evidence_text)),
                indent="      ",
            )
        )
        lines.extend(
            _wrapped_line("Rule explanation", finding.explanation, indent="      ")
        )
        lines.append("")

    lines.append("  Checks not performed:")
    if result.checks_incomplete:
        for check in result.checks_incomplete:
            lines.append(f"    - {check}")
    else:
        lines.append("    - None recorded")
    lines.append("  Limitations:")
    for item in result.limitations:
        lines.extend(_wrapped_bullet(item))
    return "\n".join(lines).rstrip() + "\n"


def _render_ai_human(ai_payload: dict) -> str:
    lines = ["2. Stage 2 AI interpretation (advisory):"]
    if ai_payload.get("status") != "complete":
        error = ai_payload.get("error", {})
        status = "Invalid" if ai_payload.get("status") == "invalid" else "Unavailable"
        lines.append(
            f"  Status: {status} ({error.get('code', 'internal_error')})"
        )
        lines.extend(
            _wrapped_line(
                "Diagnostic",
                error.get("message", "AI interpretation could not be completed."),
            )
        )
        lines.append("  Stage 1 findings and risk band remain authoritative.")
        return "\n".join(lines)

    lines.extend(
        [
            "  Status: complete",
            f"  Model: {ai_payload['model']}",
            f"  Uncertainty: {ai_payload['uncertainty']}",
        ]
    )
    lines.extend(_wrapped_line("Summary", ai_payload["summary"]))
    lines.extend(_wrapped_line("Likely intent", ai_payload["likely_intent"]))
    lines.extend(_wrapped_line("Tactics", ", ".join(ai_payload["tactics"])))
    for item in ai_payload["finding_explanations"]:
        lines.extend(
            _wrapped_line(
                f"Finding {item['finding_id']}",
                item["interpretation"],
                indent="  ",
            )
        )
    for heading, key in (
        ("Uncertainty reasons", "uncertainty_reasons"),
        ("Alternative explanations", "alternative_explanations"),
        ("Recommended actions", "recommended_actions"),
    ):
        if ai_payload[key]:
            lines.append(f"  {heading}:")
            for item in ai_payload[key]:
                lines.extend(_wrapped_bullet(item))
    lines.extend(_wrapped_line("Advisory", ai_payload["advisory"]))
    return "\n".join(lines)


def _render_decision_human(decision_payload: dict) -> str:
    lines = [
        "3. Stage 3 deterministic decision:",
        f"  Policy version: {decision_payload['risk_policy_version']}",
        f"  Stage 1 risk band: {decision_payload['stage1_risk_band'] or 'not supplied'}",
        f"  Final risk band: {decision_payload['final_risk_band']}",
        f"  Stage 2 status: {decision_payload['ai_status']}",
        f"  Uncertainty: {decision_payload['uncertainty']}",
    ]
    lines.extend(_wrapped_line("Rationale", decision_payload["rationale"]))
    lines.append("  Policy rules:")
    for rule in decision_payload["policy_rules"]:
        lines.extend(_wrapped_bullet(rule, indent="    "))
    lines.append("  Supporting findings:")
    if decision_payload["supporting_finding_ids"]:
        lines.append(
            "    " + ", ".join(decision_payload["supporting_finding_ids"])
        )
    else:
        lines.append("    None")
    if decision_payload["uncertainty_reasons"]:
        lines.append("  Uncertainty and incomplete-check notes:")
        for reason in decision_payload["uncertainty_reasons"]:
            lines.extend(_wrapped_bullet(reason))
    lines.append("  Recommended actions:")
    for item in decision_payload["recommendations"]:
        lines.extend(
            _wrapped_bullet(
                f"[{item['priority']}] {item['action']} "
                f"(reason: {item['reason']}; supporting findings: "
                f"{', '.join(item['supporting_finding_ids']) or 'none'})"
            )
        )
    if decision_payload["notes"]:
        lines.append("  Decision notes:")
        for item in decision_payload["notes"]:
            lines.extend(_wrapped_bullet(item))
    return "\n".join(lines)


def _emit_json(payload: dict, stdout: TextIO) -> None:
    stdout.write(json.dumps(payload, ensure_ascii=False, indent=2))
    stdout.write("\n")


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    json_mode = "--json" in (argv if argv is not None else sys.argv[1:])
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except ArgumentError as exc:
        message = str(exc)
        print(f"error: {message}", file=err)
        print("Use --text or --file (exactly one).", file=err)
        if json_mode:
            _emit_json({"error": message, "analysis_status": "input_error"}, out)
        return 2

    try:
        if args.text is not None:
            result = analyse_message(args.text, max_bytes=args.max_bytes)
        else:
            result = analyse_file(args.file, max_bytes=args.max_bytes)
    except InputError as exc:
        print(f"error: {exc}", file=err)
        if json_mode:
            _emit_json({"error": str(exc), "analysis_status": "input_error"}, out)
        return 1
    except Exception as exc:  # unexpected failure — no traceback to ordinary users
        print(f"error: unexpected failure ({type(exc).__name__})", file=err)
        if json_mode:
            _emit_json(
                {
                    "error": "unexpected failure",
                    "analysis_status": "failed",
                },
                out,
            )
        return 1

    payload = result.to_dict()
    ai_payload: dict | None = None
    if args.ai:
        from scamsentry.ai.analysis import analyse_with_ai
        from scamsentry.ai.ollama_provider import OllamaProvider
        from scamsentry.ai.provider import AIAnalysisError, AIErrorCode

        try:
            provider = OllamaProvider(
                model=args.ai_model,
                timeout=args.ai_timeout,
            )
            ai_payload = analyse_with_ai(
                result.original_message,
                result,
                provider,
                timeout=args.ai_timeout,
            ).to_dict()
        except AIAnalysisError as exc:
            status = (
                "invalid"
                if exc.code
                in {
                    AIErrorCode.EMPTY_OUTPUT,
                    AIErrorCode.INVALID_JSON,
                    AIErrorCode.INVALID_SCHEMA,
                    AIErrorCode.OUTPUT_TOO_LARGE,
                }
                else "unavailable"
            )
            ai_payload = {
                "status": status,
                "schema_version": "1.0",
                "model": exc.model_id or args.ai_model,
                "error": {
                    "code": exc.code.value,
                    "message": exc.message,
                },
            }
            print(
                f"warning: AI interpretation {status} "
                f"({exc.code.value}): {exc.message}",
                file=err,
            )
        except Exception as exc:
            ai_payload = {
                "status": "unavailable",
                "schema_version": "1.0",
                "model": args.ai_model,
                "error": {
                    "code": AIErrorCode.INTERNAL_ERROR.value,
                    "message": "AI analysis failed unexpectedly.",
                },
            }
            print(
                "warning: AI interpretation unavailable "
                f"({type(exc).__name__}); Stage 1 results are unchanged.",
                file=err,
            )
        payload["ai_analysis"] = ai_payload

    decision_payload: dict | None = None
    if args.decision or args.ai:
        from scamsentry.decision import assess

        complete_ai = (
            ai_payload if ai_payload is not None and ai_payload.get("status") == "complete" else None
        )
        decision_payload = assess(
            result,
            complete_ai,
            ai_status=(
                ai_payload["status"]
                if args.ai and complete_ai is None
                else None
            ),
        ).to_dict()
        payload["decision"] = decision_payload

    if args.json:
        _emit_json(payload, out)
    else:
        out.write(_render_human(result, include_message=args.include_message))
        if ai_payload is not None:
            out.write("\n")
            out.write(_render_ai_human(ai_payload))
        if decision_payload is not None:
            out.write("\n")
            out.write(_render_decision_human(decision_payload))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
