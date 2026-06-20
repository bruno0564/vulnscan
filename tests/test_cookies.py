"""Tests del check de cookies, sin tocar la red (respuestas falsas)."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.cookies import check_cookies


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_insecure_cookie_flags_all_missing_attributes() -> None:
    responses.add(
        responses.GET,
        "https://test.local",
        headers={"Set-Cookie": "sid=abc"},  # sin Secure, HttpOnly ni SameSite
        status=200,
    )

    findings = check_cookies(_context("https://test.local"))

    assert len(findings) == 1
    issues = findings[0]["issues"]
    assert findings[0]["cookie"] == "sid"
    assert any("Secure" in i for i in issues)
    assert any("HttpOnly" in i for i in issues)
    assert any("SameSite" in i for i in issues)


@responses.activate
def test_fully_secured_cookie_is_not_flagged() -> None:
    responses.add(
        responses.GET,
        "https://secure.local",
        headers={"Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"},
        status=200,
    )

    findings = check_cookies(_context("https://secure.local"))

    assert findings == []


@responses.activate
def test_lowercase_flags_are_not_false_positives() -> None:
    """Regresión: los flags son case-insensitive (RFC 6265).

    Un servidor que manda `httponly`/`samesite` en minúsculas está igual de
    seguro; no debe reportarse como si le faltaran.
    """
    responses.add(
        responses.GET,
        "https://lower.local",
        headers={"Set-Cookie": "sid=abc; secure; httponly; samesite=lax"},
        status=200,
    )

    findings = check_cookies(_context("https://lower.local"))

    assert findings == []


@responses.activate
def test_partially_secured_cookie_flags_only_the_gap() -> None:
    responses.add(
        responses.GET,
        "https://partial.local",
        headers={"Set-Cookie": "sid=abc; Secure; HttpOnly"},  # falta SameSite
        status=200,
    )

    findings = check_cookies(_context("https://partial.local"))

    assert len(findings) == 1
    issues = findings[0]["issues"]
    assert issues == ["SameSite not set — CSRF risk"]


@responses.activate
def test_no_cookies_no_findings() -> None:
    responses.add(responses.GET, "https://plain.local", status=200)

    findings = check_cookies(_context("https://plain.local"))

    assert findings == []
