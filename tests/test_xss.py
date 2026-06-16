"""Tests del check de XSS reflejado, con un servidor falso que refleja o escapa."""

import html
import re
from urllib.parse import parse_qs, urlparse

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.xss import check_xss


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


def _query_values(request: requests.PreparedRequest) -> list[str]:
    assert request.url is not None
    qs = parse_qs(urlparse(request.url).query, keep_blank_values=True)
    return [v for values in qs.values() for v in values]


def _reflecting(request: requests.PreparedRequest) -> tuple[int, dict[str, str], str]:
    """Devuelve los valores recibidos TAL CUAL en el cuerpo (vulnerable)."""
    body = "<html>" + " ".join(_query_values(request)) + "</html>"
    return (200, {}, body)


def _escaping(request: requests.PreparedRequest) -> tuple[int, dict[str, str], str]:
    """Devuelve los valores recibidos pero HTML-escapados (seguro)."""
    body = "<html>" + " ".join(html.escape(v) for v in _query_values(request)) + "</html>"
    return (200, {}, body)


@responses.activate
def test_unescaped_reflection_is_flagged_per_param() -> None:
    responses.add_callback(
        responses.GET, re.compile(r"https://app\.local/.*"), callback=_reflecting
    )

    findings = check_xss(_context("https://app.local/s?q=hi&page=1"))

    flagged = {f["param"] for f in findings}
    assert flagged == {"q", "page"}
    assert all(f["type"] == "reflected_xss" for f in findings)
    assert all(f["severity"] == "medium" for f in findings)


@responses.activate
def test_escaped_reflection_is_not_flagged() -> None:
    responses.add_callback(responses.GET, re.compile(r"https://app\.local/.*"), callback=_escaping)

    findings = check_xss(_context("https://app.local/s?q=hi"))

    assert findings == []


@responses.activate
def test_no_query_params_means_no_findings() -> None:
    responses.add(responses.GET, "https://app.local/", status=200, body="ok")

    findings = check_xss(_context("https://app.local/"))

    assert findings == []
    # Sin parámetros no debe hacer peticiones de prueba (solo la del contexto).
    assert len(responses.calls) == 1
