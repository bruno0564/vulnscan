"""Tests del check de CORS, sin tocar la red (respuestas falsas)."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.cors import PROBE_ORIGIN, check_cors


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_wildcard_origin_is_flagged_medium() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={"Access-Control-Allow-Origin": "*"},
        status=200,
    )

    findings = check_cors(_context("https://api.local"))

    assert len(findings) == 1
    assert findings[0]["type"] == "cors_wildcard"
    assert findings[0]["severity"] == "medium"


@responses.activate
def test_origin_reflection_without_credentials_is_medium() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={"Access-Control-Allow-Origin": PROBE_ORIGIN},
        status=200,
    )

    findings = check_cors(_context("https://api.local"))

    assert len(findings) == 1
    assert findings[0]["type"] == "cors_reflection"
    assert findings[0]["severity"] == "medium"


@responses.activate
def test_origin_reflection_with_credentials_is_high() -> None:
    """Reflejar el origen Y permitir credenciales es lo peligroso de verdad."""
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={
            "Access-Control-Allow-Origin": PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        status=200,
    )

    findings = check_cors(_context("https://api.local"))

    assert len(findings) == 1
    assert findings[0]["type"] == "cors_reflection"
    assert findings[0]["severity"] == "high"


@responses.activate
def test_no_cors_headers_is_clean() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(responses.OPTIONS, "https://api.local", status=200)

    findings = check_cors(_context("https://api.local"))

    assert findings == []


@responses.activate
def test_network_failure_does_not_raise() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        body=requests.ConnectionError("boom"),
    )

    findings = check_cors(_context("https://api.local"))

    assert findings == []
