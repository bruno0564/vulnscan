"""Tests del exportador SARIF."""

import json
from typing import Any

from vulnscan.sarif import render_sarif
from vulnscan.types import ScanResult


def _parse(result: ScanResult) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(render_sarif(result))
    return doc


def test_sarif_has_valid_skeleton() -> None:
    result: ScanResult = {"url": "https://example.com", "status": 200, "findings": []}

    doc = _parse(result)

    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "vulnscan"
    assert doc["runs"][0]["results"] == []


def test_severity_maps_to_sarif_level() -> None:
    result: ScanResult = {
        "url": "https://example.com",
        "status": 200,
        "findings": [
            {"type": "sql_injection", "severity": "high", "detail": "boom"},
            {"type": "missing_header", "severity": "medium", "detail": "no CSP"},
            {"type": "info_disclosure", "severity": "low", "detail": "Server header"},
        ],
    }

    results = _parse(result)["runs"][0]["results"]

    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels == {
        "sql_injection": "error",
        "missing_header": "warning",
        "info_disclosure": "note",
    }


def test_rules_are_deduplicated_and_indexed() -> None:
    result: ScanResult = {
        "url": "https://example.com",
        "status": 200,
        "findings": [
            {"type": "missing_header", "severity": "medium", "detail": "no CSP"},
            {"type": "missing_header", "severity": "medium", "detail": "no HSTS"},
            {"type": "open_redirect", "severity": "medium", "detail": "redirects out"},
        ],
    }

    doc = _parse(result)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]

    # Dos hallazgos del mismo tipo -> una sola regla.
    assert [r["id"] for r in rules] == ["missing_header", "open_redirect"]
    # ruleIndex apunta a la regla correcta en el array.
    for r in results:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


def test_message_and_location_come_from_finding() -> None:
    result: ScanResult = {
        "url": "https://example.com/app",
        "status": 200,
        "findings": [{"type": "open_redirect", "severity": "medium", "detail": "redirects out"}],
    }

    result_obj = _parse(result)["runs"][0]["results"][0]

    assert result_obj["message"]["text"] == "redirects out"
    uri = result_obj["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/app"


def test_error_result_produces_valid_empty_run() -> None:
    result: ScanResult = {"url": "https://down.local", "error": "boom", "findings": []}

    doc = _parse(result)

    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
