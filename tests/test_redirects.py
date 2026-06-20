"""Tests del check de open redirect, sin tocar la red."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.redirects import check_redirects


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5, allow_redirects=False)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_external_redirect_is_flagged() -> None:
    url = "https://app.local/login?next=/home"
    # La respuesta inicial para construir el contexto.
    responses.add(responses.GET, "https://app.local/login", status=200)
    # La sonda redirige a un host externo controlado por el atacante.
    responses.add(
        responses.GET,
        "https://app.local/login",
        status=302,
        headers={"Location": "https://evil.example.com/"},
    )

    findings = check_redirects(_context(url))

    assert len(findings) == 1
    assert findings[0]["type"] == "open_redirect"
    assert findings[0]["param"] == "next"
    assert findings[0]["severity"] == "medium"


@responses.activate
def test_no_redirect_is_clean() -> None:
    url = "https://app.local/login?next=/home"
    responses.add(responses.GET, "https://app.local/login", status=200)

    assert check_redirects(_context(url)) == []


@responses.activate
def test_same_host_redirect_is_not_flagged() -> None:
    """Redirigir dentro del propio dominio no es un open redirect."""
    url = "https://app.local/login?next=/home"
    responses.add(responses.GET, "https://app.local/login", status=200)
    responses.add(
        responses.GET,
        "https://app.local/login",
        status=302,
        headers={"Location": "https://app.local/home"},
    )

    assert check_redirects(_context(url)) == []
