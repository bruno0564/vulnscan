"""Tests del check de rutas expuestas, incluido el filtro anti soft-404."""

import re

import requests
import responses

from vulnscan.checks.base import ScanContext
from vulnscan.checks.directories import check_directories


def _context(url: str) -> ScanContext:
    session = requests.Session()
    response = session.get(url, timeout=5)
    return ScanContext(url=url, session=session, response=response)


@responses.activate
def test_real_exposed_path_on_a_normal_server_is_flagged() -> None:
    # Página principal (para el contexto).
    responses.add(responses.GET, "https://target.local/", status=200)
    # Servidor normal: una ruta sensible existe (200), el resto no (404).
    responses.add(responses.GET, "https://target.local/.env", status=200, body="SECRET=1")
    responses.add(responses.GET, re.compile(r"https://target\.local/.+"), status=404)

    findings = check_directories(_context("https://target.local/"))

    paths = {f["path"] for f in findings}
    assert "/.env" in paths
    assert all(f["type"] == "exposed_path" for f in findings)


@responses.activate
def test_catch_all_server_returns_no_false_positives() -> None:
    # Cualquier ruta -> mismo 200 con el mismo cuerpo (página comodín / soft-404).
    responses.add(responses.GET, "https://catchall.local/", status=200, body="<html>home</html>")
    responses.add(
        responses.GET,
        re.compile(r"https://catchall\.local/.+"),
        status=200,
        body="<html>same page for everything</html>",
    )

    findings = check_directories(_context("https://catchall.local/"))

    assert findings == []


@responses.activate
def test_catch_all_still_flags_paths_with_different_content() -> None:
    responses.add(responses.GET, "https://catchall.local/", status=200, body="x")

    def _callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], str]:
        assert request.url is not None
        # /.git/HEAD devuelve un cuerpo claramente distinto; el resto, la comodín.
        if request.url.endswith("/.git/HEAD"):
            return (200, {}, "ref: refs/heads/main\n" + "A" * 200)
        return (200, {}, "<html>same page for everything</html>")

    responses.add_callback(
        responses.GET, re.compile(r"https://catchall\.local/.+"), callback=_callback
    )

    findings = check_directories(_context("https://catchall.local/"))

    paths = {f["path"] for f in findings}
    assert paths == {"/.git/HEAD"}
