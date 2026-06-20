"""Tests del check de TLS / certificado.

La lógica de evaluación (`_inspect`) se testea directamente; las rutas que abren
un socket TLS real se sustituyen con monkeypatch, sin tocar la red.
"""

import ssl

import pytest
import requests

from vulnscan.checks import tls
from vulnscan.checks.base import ScanContext

_DAY = 86400.0
_NOW = 1_700_000_000.0  # epoch de referencia fijo para los tests


def _context(url: str) -> ScanContext:
    response = requests.Response()
    response.status_code = 200
    return ScanContext(url=url, session=requests.Session(), response=response)


# --- _inspect: lógica pura ------------------------------------------------


def test_healthy_certificate_and_protocol_is_clean() -> None:
    assert tls._inspect("TLSv1.3", _NOW + 90 * _DAY, now=_NOW) == []


def test_weak_protocol_is_flagged() -> None:
    findings = tls._inspect("TLSv1", _NOW + 90 * _DAY, now=_NOW)
    assert len(findings) == 1
    assert findings[0]["type"] == "weak_tls_version"
    assert findings[0]["severity"] == "medium"


def test_sslv3_is_high_severity() -> None:
    findings = tls._inspect("SSLv3", _NOW + 90 * _DAY, now=_NOW)
    assert findings[0]["severity"] == "high"


def test_expired_certificate_is_high() -> None:
    findings = tls._inspect("TLSv1.2", _NOW - 5 * _DAY, now=_NOW)
    assert len(findings) == 1
    assert findings[0]["type"] == "expired_certificate"
    assert findings[0]["severity"] == "high"


def test_soon_to_expire_certificate_is_flagged() -> None:
    findings = tls._inspect("TLSv1.2", _NOW + 3 * _DAY, now=_NOW)
    assert len(findings) == 1
    assert findings[0]["type"] == "expiring_certificate"
    assert findings[0]["severity"] == "medium"


# --- check_tls: orquestación (socket monkeypatcheado) ---------------------


def test_http_url_is_skipped() -> None:
    assert tls.check_tls(_context("http://insecure.local")) == []


def test_certificate_verification_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(host: str, port: int, timeout: float) -> tuple[str | None, float | None]:
        raise ssl.SSLCertVerificationError("self-signed certificate")

    monkeypatch.setattr(tls, "_connect", _boom)

    findings = tls.check_tls(_context("https://selfsigned.local"))

    assert len(findings) == 1
    assert findings[0]["type"] == "invalid_certificate"
    assert findings[0]["severity"] == "high"


def test_connection_error_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(host: str, port: int, timeout: float) -> tuple[str | None, float | None]:
        raise OSError("connection refused")

    monkeypatch.setattr(tls, "_connect", _boom)

    assert tls.check_tls(_context("https://down.local")) == []


def test_healthy_connection_reports_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def _ok(host: str, port: int, timeout: float) -> tuple[str | None, float | None]:
        # cert válido y lejano en el tiempo
        far_future = ssl.cert_time_to_seconds("Jan  1 00:00:00 2999 GMT")
        return "TLSv1.3", far_future

    monkeypatch.setattr(tls, "_connect", _ok)

    assert tls.check_tls(_context("https://good.local")) == []
