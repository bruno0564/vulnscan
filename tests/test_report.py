"""Tests del informe HTML (report.render_html)."""

from vulnscan.report import render_html
from vulnscan.types import Finding, ScanResult, Summary


def _result(findings: list[Finding]) -> ScanResult:
    summary: Summary = {
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
    }
    return {
        "url": "https://target.local/",
        "status": 200,
        "findings": findings,
        "summary": summary,
    }


def test_renders_valid_standalone_document() -> None:
    html = render_html(_result([]))
    assert html.startswith("<!doctype html>")
    assert "<style>" in html  # CSS embebido -> autocontenido
    assert "No issues found" in html


def test_findings_appear_in_the_table() -> None:
    findings: list[Finding] = [
        {
            "type": "missing_header",
            "severity": "medium",
            "header": "Content-Security-Policy",
            "detail": "Missing — XSS protection weakened",
        },
        {
            "type": "subdomain",
            "severity": "low",
            "host": "dev.target.local",
            "detail": "Resolvable subdomain",
        },
    ]
    html = render_html(_result(findings))

    assert "Content-Security-Policy" in html
    assert "dev.target.local" in html
    assert "1 medium" in html
    assert "1 low" in html


def test_dynamic_content_is_html_escaped() -> None:
    # El payload reflejado de un hallazgo XSS NO debe romper el propio informe.
    findings: list[Finding] = [
        {
            "type": "reflected_xss",
            "severity": "medium",
            "param": "q",
            "payload": "<svg/onload=1>",
            "detail": "Parameter 'q' is reflected unescaped",
        },
    ]
    html = render_html(_result(findings))

    assert "<svg/onload=1>" not in html  # crudo no
    assert "&lt;svg/onload=1&gt;" in html  # escapado sí


def test_error_result_is_rendered() -> None:
    result: ScanResult = {
        "error": "connection refused",
        "url": "https://down.local/",
        "findings": [],
    }
    html = render_html(result)

    assert "Error scanning" in html
    assert "connection refused" in html
