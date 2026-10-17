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
    def error(self, message: str) -> None:
        raise ArgumentError(message)


def _build_parser() -> QuietParser:
    parser = QuietParser(
        prog="scamsentry",
        description="ScamSentry: deterministic analysis with optional open-weight AI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="Analyse a message from --text or --file")
    source = analyze.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="Message text to analyse")
    source.add_argument("--file", help="UTF-8 file containing the message")
    analyze.add_argument("--json", action="store_true", help="Write structured JSON to stdout")
    analyze.add_argument("--include-message", action="store_true", help="Include original message in human output")
    analyze.add_argument("--max-bytes", type=int, default=50 * 1024, help="Maximum UTF-8 size in bytes")
    analyze.add_argument("--ai", action="store_true", help="Add Stage 2 analysis using local Ollama")
    analyze.add_argument("--ai-model", default="gemma3:4b", help="Local Ollama model (default: gemma3:4b)")
    analyze.add_argument("--ai-timeout", type=int, default=120, help="AI timeout in seconds (1-900)")
    return parser


def _truncate(text: str, limit: int = EVIDENCE_TRUNCATE) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _render_human(result: AnalysisResult, *, include_message: bool, ai_analysis: dict | None = None) -> str:
    lines = [
        "ScamSentry — deterministic analysis",
        f"Status: {result.analysis_status.value}",
        f"Risk band: {result.risk_band.value if result.risk_band else 'n/a'} (rule-based, not a probability)",
        f"Findings: {result.finding_count}", "",
    ]
    if include_message:
        lines.extend(["Original message:", result.original_message, ""])
    else:
        lines.extend(["Original message omitted (pass --include-message to show it; message text may be sensitive).", ""])
    if not result.findings:
        lines.append("No implemented checks fired. This is not a verified-safe verdict.")
    for finding in result.findings:
        offset = ""
        if finding.start_offset is not None and finding.end_offset is not None:
            offset = f" [{finding.start_offset}:{finding.end_offset}]"
        lines.extend([
            f"- {finding.id} {finding.rule_id} {finding.severity.value} ({finding.category.value}, {finding.observation_kind.value})",
            f"  {finding.title}",
            f"  evidence{offset}: {_truncate(finding.evidence_text)!r}",
            f"  {finding.explanation}", "",
        ])
    if ai_analysis and ai_analysis.get("status") == "complete":
        lines.extend([
            "Stage 2 — Open-weight AI interpretation (advisory)",
            f"Model: {ai_analysis['model']}",
            f"Summary: {ai_analysis['summary']}",
            f"Likely intent: {ai_analysis['likely_intent']}",
            f"Tactics: {', '.join(ai_analysis['tactics'])}",
            f"Uncertainty: {ai_analysis['uncertainty']}",
        ])
        lines.extend(f"  Uncertainty reason: {reason}" for reason in ai_analysis["uncertainty_reasons"])
        lines.extend(f"  {item['finding_id']}: {item['interpretation']}" for item in ai_analysis["finding_explanations"])
        lines.extend(f"  Suggested action: {action}" for action in ai_analysis["recommended_actions"])
        lines.append("AI interpretation is advisory and is not proof of maliciousness.")
    lines.extend(["", "Checks not performed: " + ", ".join(result.checks_incomplete), "Limitations:"])
    lines.extend(f"- {item}" for item in result.limitations)
    return "\n".join(lines).rstrip() + "\n"


def _emit_json(payload: dict, stdout: TextIO) -> None:
    stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def run(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    json_mode = "--json" in effective_argv
    try:
        args = _build_parser().parse_args(effective_argv)
    except ArgumentError as exc:
        print(f"error: {exc}", file=err)
        print("Use --text or --file (exactly one).", file=err)
        if json_mode:
            _emit_json({"error": str(exc), "analysis_status": "input_error"}, out)
        return 2

    if not 1 <= args.ai_timeout <= 900:
        print("error: --ai-timeout must be between 1 and 900 seconds", file=err)
        if args.json:
            _emit_json({"error": "--ai-timeout out of range", "analysis_status": "input_error"}, out)
        return 2
    if not args.ai and args.ai_model != "gemma3:4b":
        print("error: --ai-model requires --ai", file=err)
        if args.json:
            _emit_json({"error": "--ai-model requires --ai", "analysis_status": "input_error"}, out)
        return 2

    try:
        result = analyse_message(args.text, max_bytes=args.max_bytes) if args.text is not None else analyse_file(args.file, max_bytes=args.max_bytes)
    except InputError as exc:
        print(f"error: {exc}", file=err)
        if args.json:
            _emit_json({"error": str(exc), "analysis_status": "input_error"}, out)
        return 1
    except Exception as exc:
        print(f"error: unexpected failure ({type(exc).__name__})", file=err)
        if args.json:
            _emit_json({"error": "unexpected failure", "analysis_status": "failed"}, out)
        return 1

    ai_payload = None
    if args.ai:
        try:
            from scamsentry.ai import OllamaCLIProvider, analyse_with_ai
            ai_payload = analyse_with_ai(
                result.original_message, result.to_dict(), OllamaCLIProvider(args.ai_model), timeout=args.ai_timeout
            ).to_dict()
        except Exception as exc:
            message = f"AI analysis unavailable: {type(exc).__name__}: {exc}"
            print(f"warning: {message}", file=err)
            ai_payload = {
                "status": "unavailable", "model": args.ai_model, "error": message,
                "disclaimer": "Stage 1 results remain valid; no AI interpretation was produced.",
            }

    if args.json:
        payload = result.to_dict()
        if args.ai:
            payload["ai_analysis"] = ai_payload
        _emit_json(payload, out)
    else:
        out.write(_render_human(result, include_message=args.include_message, ai_analysis=ai_payload))
        if args.ai and ai_payload and ai_payload.get("status") == "unavailable":
            out.write("Stage 2 AI interpretation: unavailable; see stderr for details.\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return run(argv)


if __name__ == "__main__":
    sys.exit(main())
