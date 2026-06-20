"""Tests del check de security.txt (RFC 9116), sin tocar la red."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.security_txt import check_security_txt


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_missing_security_txt_is_flagged() -> None:
    responses.add(responses.GET, "https://site.local/", status=200)
    responses.add(responses.GET, "https://site.local/.well-known/security.txt", status=404)
    responses.add(responses.GET, "https://site.local/security.txt", status=404)

    findings = check_security_txt(_context("https://site.local/"))

    assert len(findings) == 1
    assert findings[0]["type"] == "missing_security_txt"
    assert findings[0]["severity"] == "low"


@responses.activate
def test_valid_security_txt_is_not_flagged() -> None:
    responses.add(responses.GET, "https://site.local/", status=200)
    responses.add(
        responses.GET,
        "https://site.local/.well-known/security.txt",
        body="Contact: mailto:security@site.local\nExpires: 2030-01-01T00:00:00Z\n",
        status=200,
    )

    assert check_security_txt(_context("https://site.local/")) == []


@responses.activate
def test_200_without_contact_field_is_not_a_valid_file() -> None:
    """Un 200 que devuelve la home (sin campo Contact:) no cuenta como security.txt."""
    responses.add(responses.GET, "https://site.local/", status=200)
    responses.add(
        responses.GET,
        "https://site.local/.well-known/security.txt",
        body="<!doctype html><html>not found</html>",
        status=200,
    )
    responses.add(
        responses.GET,
        "https://site.local/security.txt",
        body="<!doctype html><html>not found</html>",
        status=200,
    )

    findings = check_security_txt(_context("https://site.local/"))

    assert len(findings) == 1
    assert findings[0]["type"] == "missing_security_txt"
