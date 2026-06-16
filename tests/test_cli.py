"""Tests de la CLI (main) — parseo de flags y salidas, con scan() mockeado."""

import json
from pathlib import Path

import pytest

from vulnscan import cli
from vulnscan.types import ScanResult

_FAKE_RESULT: ScanResult = {
    "url": "https://target.local/",
    "status": 200,
    "findings": [
        {
            "type": "missing_header",
            "severity": "medium",
            "header": "Content-Security-Policy",
            "detail": "Missing",
        }
    ],
    "summary": {"high": 0, "medium": 1, "low": 0},
}


@pytest.fixture(autouse=True)
def _mock_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evita cualquier tráfico de red: scan() devuelve siempre el mismo resultado."""
    monkeypatch.setattr(cli, "scan", lambda *a, **k: _FAKE_RESULT)


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> None:
    monkeypatch.setattr("sys.argv", ["vulnscan", *argv])
    cli.main()


def test_text_report_is_printed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(monkeypatch, "https://target.local")
    out = capsys.readouterr().out
    assert "Target: https://target.local/" in out
    assert "Content-Security-Policy" in out


def test_json_output_is_valid(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _run(monkeypatch, "https://target.local", "--json")
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"]["medium"] == 1


def test_html_flag_writes_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    out_file = tmp_path / "report.html"
    _run(monkeypatch, "https://target.local", "--html", str(out_file))

    assert out_file.exists()
    assert "<!doctype html>" in out_file.read_text(encoding="utf-8")
    assert f"HTML report written to {out_file}" in capsys.readouterr().out


def test_invalid_auth_combo_exits_with_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        _run(monkeypatch, "https://target.local", "--bearer", "x", "--basic", "a:b")
