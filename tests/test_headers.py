"""Tests del check de cabeceras, sin tocar la red (respuestas falsas)."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.headers import check_headers


def _context(url: str) -> ScanContext:
    """Construye un ScanContext con una respuesta ya mockeada por @responses.activate."""
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_missing_security_headers_are_flagged() -> None:
    responses.add(responses.GET, "https://test.local", headers={}, status=200)

    findings = check_headers(_context("https://test.local"))

    types = {f["type"] for f in findings}
    assert "missing_header" in types
    # Falta CSP -> debe aparecer como hallazgo medium
    assert any(f.get("header") == "Content-Security-Policy" for f in findings)


@responses.activate
def test_present_headers_are_not_flagged_as_missing() -> None:
    secure = {
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    responses.add(responses.GET, "https://secure.local", headers=secure, status=200)

    findings = check_headers(_context("https://secure.local"))

    missing = [f for f in findings if f["type"] == "missing_header"]
    assert missing == []


@responses.activate
def test_info_disclosure_header_is_flagged() -> None:
    responses.add(
        responses.GET,
        "https://leaky.local",
        headers={"Server": "Apache/2.4.41"},
        status=200,
    )

    findings = check_headers(_context("https://leaky.local"))

    server = [f for f in findings if f.get("header") == "Server"]
    assert server and server[0]["severity"] == "low"
    assert server[0]["value"] == "Apache/2.4.41"
