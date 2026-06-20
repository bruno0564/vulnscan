"""El escaneo concurrente debe dar exactamente el mismo informe que el secuencial."""

import socket

import pytest
import responses

from vulnscan.checks import tls
from vulnscan.scanner import _run_checks, scan


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "gethostbyname", lambda *_a, **_k: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(tls, "_connect", lambda *_a, **_k: (_ for _ in ()).throw(OSError()))


@responses.activate
def test_concurrent_and_sequential_results_match() -> None:
    import re

    responses.add(responses.GET, "https://target.local/", headers={}, status=200)
    responses.add(responses.OPTIONS, "https://target.local/", status=200)
    responses.add(responses.GET, re.compile(r"https://target\.local/.+"), status=404)

    sequential = scan("https://target.local/", workers=1)

    responses.reset()
    responses.add(responses.GET, "https://target.local/", headers={}, status=200)
    responses.add(responses.OPTIONS, "https://target.local/", status=200)
    responses.add(responses.GET, re.compile(r"https://target\.local/.+"), status=404)

    concurrent = scan("https://target.local/", workers=8)

    assert concurrent["findings"] == sequential["findings"]
    assert concurrent["summary"] == sequential["summary"]


def test_run_checks_preserves_registration_order() -> None:
    """Aunque los hilos terminen en otro orden, los hallazgos van por orden de check."""
    from vulnscan.checks.base import ScanContext

    def check_a(_ctx: ScanContext) -> list:  # type: ignore[type-arg]
        return [{"type": "a", "severity": "low"}]

    def check_b(_ctx: ScanContext) -> list:  # type: ignore[type-arg]
        return [{"type": "b", "severity": "low"}]

    ctx = object()  # los checks de prueba no lo usan
    findings = _run_checks([check_a, check_b], ctx, workers=8)  # type: ignore[arg-type]

    assert [f["type"] for f in findings] == ["a", "b"]
