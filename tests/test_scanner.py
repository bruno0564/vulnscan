"""Test de integración del orquestador `scan()`."""

import re
import socket

import pytest
import requests
import responses

from vulnscan.checks import tls
from vulnscan.scanner import scan


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neutraliza los checks que salen a la red fuera de `requests`.

    `subdomains` resuelve DNS y `tls` abre un socket TLS: `responses` no los
    intercepta, así que aquí los desactivamos para que la prueba sea offline.
    """

    def _no_dns(*_args: object, **_kwargs: object) -> str:
        raise OSError("no DNS in tests")

    def _no_tls(*_args: object, **_kwargs: object) -> tuple[str | None, float | None]:
        raise OSError("no TLS in tests")

    monkeypatch.setattr(socket, "gethostbyname", _no_dns)
    monkeypatch.setattr(tls, "_connect", _no_tls)


@responses.activate
def test_scan_returns_structured_report() -> None:
    # Respuesta principal sin cabeceras de seguridad (se registra primero -> gana
    # en la URL raíz exacta).
    responses.add(responses.GET, "https://target.local/", headers={}, status=200)
    # OPTIONS para el check de CORS.
    responses.add(responses.OPTIONS, "https://target.local/", status=200)
    # Cualquier otro path probado por el check de directorios -> 404.
    responses.add(responses.GET, re.compile(r"https://target\.local/.+"), status=404)

    result = scan("https://target.local/")

    assert result["status"] == 200
    assert "summary" in result
    assert result["summary"]["medium"] >= 1  # faltan cabeceras de seguridad
    # El informe va ordenado por severidad (high -> medium -> low).
    order = {"high": 0, "medium": 1, "low": 2}
    severities = [order[f["severity"]] for f in result["findings"]]
    assert severities == sorted(severities)


@responses.activate
def test_scan_handles_unreachable_host() -> None:
    responses.add(
        responses.GET,
        "https://down.local/",
        body=requests.ConnectionError("boom"),
    )

    result = scan("https://down.local/")

    assert "error" in result
    assert result["findings"] == []
