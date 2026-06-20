"""Tests del check de clickjacking, sin tocar la red (respuestas falsas)."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.clickjacking import check_clickjacking


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_no_protection_is_flagged() -> None:
    responses.add(responses.GET, "https://framable.local", headers={}, status=200)

    findings = check_clickjacking(_context("https://framable.local"))

    assert len(findings) == 1
    assert findings[0]["type"] == "clickjacking"
    assert findings[0]["severity"] == "medium"


@responses.activate
def test_x_frame_options_deny_is_safe() -> None:
    responses.add(
        responses.GET,
        "https://safe.local",
        headers={"X-Frame-Options": "DENY"},
        status=200,
    )

    assert check_clickjacking(_context("https://safe.local")) == []


@responses.activate
def test_x_frame_options_sameorigin_lowercase_is_safe() -> None:
    responses.add(
        responses.GET,
        "https://safe.local",
        headers={"X-Frame-Options": "sameorigin"},
        status=200,
    )

    assert check_clickjacking(_context("https://safe.local")) == []


@responses.activate
def test_csp_frame_ancestors_is_safe() -> None:
    """CSP frame-ancestors sustituye a X-Frame-Options: no debe marcarse."""
    responses.add(
        responses.GET,
        "https://modern.local",
        headers={"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
        status=200,
    )

    assert check_clickjacking(_context("https://modern.local")) == []


@responses.activate
def test_deprecated_allow_from_is_not_considered_protection() -> None:
    responses.add(
        responses.GET,
        "https://old.local",
        headers={"X-Frame-Options": "ALLOW-FROM https://trusted.local"},
        status=200,
    )

    findings = check_clickjacking(_context("https://old.local"))

    assert len(findings) == 1
