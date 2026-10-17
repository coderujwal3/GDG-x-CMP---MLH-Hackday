from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

from scamsentry.cli import run

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _run(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    code = run(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_cli_text_human() -> None:
    code, out, err = _run(["analyze", "--text", "hello there colleague"])
    assert code == 0
    assert "LOW_CONCERN" in out
    assert "Original message omitted" in out
    assert err == ""


def test_cli_include_message() -> None:
    code, out, _ = _run(
        ["analyze", "--text", "hello there colleague", "--include-message"]
    )
    assert code == 0
    assert "hello there colleague" in out


def test_cli_file_json() -> None:
    code, out, err = _run(
        ["analyze", "--file", str(EXAMPLES / "suspicious_message.txt"), "--json"]
    )
    assert code == 0
    assert err == ""
    payload = json.loads(out)
    assert payload["risk_band"] == "HIGH_CONCERN"
    assert payload["finding_count"] >= 2


def test_cli_exactly_one_source() -> None:
    code, out, err = _run(["analyze", "--text", "hi", "--file", "x.txt"])
    assert code == 2
    assert "error:" in err


def test_cli_empty_text_nonzero() -> None:
    code, out, err = _run(["analyze", "--text", "   "])
    assert code == 1
    assert "error:" in err
    assert out == ""


def test_cli_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "no_such_file_scamsentry.txt"
    code, _, err = _run(["analyze", "--file", str(missing)])
    assert code == 1
    assert "not found" in err.lower() or "error:" in err


def test_cli_json_input_error() -> None:
    code, out, err = _run(["analyze", "--text", "   ", "--json"])
    assert code == 1
    assert "error:" in err
    payload = json.loads(out)
    assert payload["analysis_status"] == "input_error"


def test_cli_file_path_with_spaces_and_unicode(tmp_path: Path) -> None:
    folder = tmp_path / "scam reports 2026" / "dossier été"
    folder.mkdir(parents=True)
    msg_file = folder / "message à vérifier.txt"
    msg_file.write_text("Hello team, just checking in.", encoding="utf-8")
    code, out, err = _run(["analyze", "--file", str(msg_file)])
    assert code == 0
    assert "LOW_CONCERN" in out
    assert err == ""


def test_cli_module_help() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "scamsentry.cli", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "usage:" in proc.stdout
    assert "analyze" in proc.stdout


def test_cli_module_entrypoint() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "scamsentry.cli", "analyze", "--text", "hello world"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "LOW_CONCERN" in proc.stdout
    assert proc.stderr == ""


def test_cli_package_entrypoint() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "scamsentry", "analyze", "--text", "hello world"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "LOW_CONCERN" in proc.stdout
    assert proc.stderr == ""


def test_cli_main_wrapper() -> None:
    from scamsentry.cli import main
    assert main(["analyze", "--text", "hello friend"]) == 0


def test_cli_oversized_text() -> None:
    code, out, err = _run(["analyze", "--text", "hello world", "--max-bytes", "5"])
    assert code == 1
    assert "exceeds" in err

