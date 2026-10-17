"""Command-line interface. Diagnostics on stderr; JSON on stdout."""

from __future__ import annotations

import argparse
import json
import sys
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


def _build_parser() -> QuietParser:
    parser = QuietParser(
        prog="scamsentry",
        description=(
            "ScamSentry AI Stage 1: deterministic offline analysis of message text. "
            "Findings are indicators, not proof of a scam."
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
    return parser


def _truncate(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1] + "…"


def _render_human(result: AnalysisResult, *, include_message: bool) -> str:
    lines: list[str] = [
        "ScamSentry AI — Stage 1 deterministic analysis",
        f"Status: {result.analysis_status.value}",
        f"Risk band: {result.risk_band.value if result.risk_band else 'n/a'} "
        "(rule-based policy, not a probability)",
        f"Findings: {result.finding_count}",
        "",
    ]
    if include_message:
        lines.append("Original message:")
        lines.append(result.original_message)
        lines.append("")
    else:
        lines.append(
            "Original message omitted (pass --include-message to show it; "
            "message text may be sensitive)."
        )
        lines.append("")

    if not result.findings:
        lines.append("No implemented checks fired. This is not a verified-safe verdict.")
    for finding in result.findings:
        offset = ""
        if finding.start_offset is not None and finding.end_offset is not None:
            offset = f" [{finding.start_offset}:{finding.end_offset}]"
        lines.append(
            f"- {finding.id} {finding.rule_id} {finding.severity.value} "
            f"({finding.category.value}, {finding.observation_kind.value})"
        )
        lines.append(f"  {finding.title}")
        lines.append(f"  evidence{offset}: {_truncate(finding.evidence_text)!r}")
        lines.append(f"  {finding.explanation}")
        lines.append("")

    lines.append("Checks not performed: " + ", ".join(result.checks_incomplete))
    lines.append("Limitations:")
    for item in result.limitations:
        lines.append(f"- {item}")
    return "\n".join(lines).rstrip() + "\n"


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

    if args.json:
        _emit_json(result.to_dict(), out)
    else:
        out.write(_render_human(result, include_message=args.include_message))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
