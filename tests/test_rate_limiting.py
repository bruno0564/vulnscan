"""Tests del retardo de cortesía y el timeout configurables (ScanContext.request)."""

import requests
import responses

from vulnscan.checks.base import ScanContext


def _context(**kwargs: object) -> ScanContext:
    session = requests.Session()
    response = session.get("https://test.local/", timeout=5)
    return ScanContext(url="https://test.local/", session=session, response=response, **kwargs)  # type: ignore[arg-type]


@responses.activate
def test_request_applies_delay_before_each_call(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    responses.add(responses.GET, "https://test.local/", status=200)

    slept: list[float] = []
    monkeypatch.setattr("vulnscan.checks.base.time.sleep", slept.append)

    ctx = _context(delay=0.25)
    ctx.request("GET", "https://test.local/")

    assert slept == [0.25]


@responses.activate
def test_no_sleep_when_delay_is_zero(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    responses.add(responses.GET, "https://test.local/", status=200)

    slept: list[float] = []
    monkeypatch.setattr("vulnscan.checks.base.time.sleep", slept.append)

    ctx = _context()  # delay por defecto = 0.0
    ctx.request("GET", "https://test.local/")

    assert slept == []


@responses.activate
def test_request_fills_in_default_timeout() -> None:
    responses.add(responses.GET, "https://test.local/", status=200)

    ctx = _context(timeout=3.5)
    r = ctx.request("GET", "https://test.local/")

    # El timeout efectivo se refleja en la petición enviada.
    assert r.request is not None
    assert ctx.timeout == 3.5


@responses.activate
def test_explicit_timeout_overrides_default() -> None:
    responses.add(responses.GET, "https://test.local/", status=200)

    ctx = _context(timeout=3.5)
    # Si el check pasa su propio timeout, ctx.request no lo pisa.
    r = ctx.request("GET", "https://test.local/", timeout=1.0)

    assert r.status_code == 200
