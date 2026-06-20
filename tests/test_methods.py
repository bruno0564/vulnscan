"""Tests del check de métodos HTTP peligrosos, sin tocar la red."""

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.methods import check_methods


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_dangerous_methods_in_allow_header_are_flagged() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={"Allow": "GET, POST, PUT, DELETE, TRACE"},
        status=200,
    )

    findings = check_methods(_context("https://api.local"))

    flagged = {f["method"] for f in findings}
    assert flagged == {"PUT", "DELETE", "TRACE"}
    assert all(f["severity"] == "medium" for f in findings)


@responses.activate
def test_safe_methods_only_are_not_flagged() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={"Allow": "GET, HEAD, POST, OPTIONS"},
        status=200,
    )

    assert check_methods(_context("https://api.local")) == []


@responses.activate
def test_allow_header_is_parsed_case_insensitively() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        headers={"Allow": "get, put"},
        status=200,
    )

    findings = check_methods(_context("https://api.local"))

    assert {f["method"] for f in findings} == {"PUT"}


@responses.activate
def test_network_failure_does_not_raise() -> None:
    responses.add(responses.GET, "https://api.local", status=200)
    responses.add(
        responses.OPTIONS,
        "https://api.local",
        body=requests.ConnectionError("boom"),
    )

    assert check_methods(_context("https://api.local")) == []
