"""Tests del check de SQLi error-based, con un servidor falso que filtra errores."""

import re
from urllib.parse import parse_qs, urlparse

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.sqli import check_sqli

MYSQL_ERROR = "You have an error in your SQL syntax; check the manual"


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


def _has_quote(request: requests.PreparedRequest) -> bool:
    assert request.url is not None
    qs = parse_qs(urlparse(request.url).query, keep_blank_values=True)
    return any("'" in v for values in qs.values() for v in values)


def _error_on_quote(request: requests.PreparedRequest) -> tuple[int, dict[str, str], str]:
    """Filtra un error de MySQL solo cuando la entrada lleva una comilla."""
    body = MYSQL_ERROR if _has_quote(request) else "<html>results</html>"
    return (200, {}, body)


def _always_error(request: requests.PreparedRequest) -> tuple[int, dict[str, str], str]:
    """La página siempre muestra el error, inyectemos o no (baseline ruidoso)."""
    return (200, {}, MYSQL_ERROR)


@responses.activate
def test_db_error_triggered_by_quote_is_flagged() -> None:
    responses.add_callback(
        responses.GET, re.compile(r"https://app\.local/.*"), callback=_error_on_quote
    )

    findings = check_sqli(_context("https://app.local/item?id=1"))

    assert len(findings) == 1
    assert findings[0]["type"] == "sql_injection"
    assert findings[0]["severity"] == "high"
    assert findings[0]["param"] == "id"
    assert "MySQL" in findings[0]["detail"]


@responses.activate
def test_no_error_means_no_finding() -> None:
    responses.add_callback(
        responses.GET,
        re.compile(r"https://app\.local/.*"),
        callback=lambda req: (200, {}, "<html>all good</html>"),
    )

    findings = check_sqli(_context("https://app.local/item?id=1"))

    assert findings == []


@responses.activate
def test_preexisting_error_in_baseline_is_not_flagged() -> None:
    responses.add_callback(
        responses.GET, re.compile(r"https://app\.local/.*"), callback=_always_error
    )

    findings = check_sqli(_context("https://app.local/item?id=1"))

    # El error ya estaba en el baseline -> no atribuible a la inyección.
    assert findings == []


@responses.activate
def test_no_query_params_means_no_findings() -> None:
    responses.add(responses.GET, "https://app.local/", status=200, body="ok")

    findings = check_sqli(_context("https://app.local/"))

    assert findings == []
    assert len(responses.calls) == 1
