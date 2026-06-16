"""Tests de la enumeración de subdominios, con un resolvedor DNS falso."""

import socket

import requests

from vulnscan.checks.base import ScanContext
from vulnscan.checks.subdomains import check_subdomains


def _context(url: str, **kwargs: object) -> ScanContext:
    # El check no usa la respuesta HTTP, así que basta una Response vacía.
    return ScanContext(
        url=url,
        session=requests.Session(),
        response=requests.Response(),
        **kwargs,  # type: ignore[arg-type]
    )


def _fake_resolver(existing: set[str]):  # type: ignore[no-untyped-def]
    def resolve(host: str) -> str:
        if host in existing:
            return "203.0.113.10"
        raise socket.gaierror("name or service not known")

    return resolve


def test_resolvable_subdomains_are_flagged(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    existing = {"api.example.com", "dev.example.com", "admin.example.com"}
    monkeypatch.setattr("socket.gethostbyname", _fake_resolver(existing))

    findings = check_subdomains(_context("https://example.com/"))

    hosts = {f["host"] for f in findings}
    assert hosts == existing
    assert all(f["type"] == "subdomain" for f in findings)
    assert all(f["severity"] == "low" for f in findings)


def test_target_host_is_not_reported_as_its_own_subdomain(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Todo resuelve: aun así el propio host del objetivo no debe aparecer.
    monkeypatch.setattr("socket.gethostbyname", lambda host: "203.0.113.10")

    findings = check_subdomains(_context("https://www.example.com/"))

    hosts = {f["host"] for f in findings}
    assert "www.example.com" not in hosts


def test_ip_target_is_skipped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # No debe ni intentar resolver para una IP literal.
    monkeypatch.setattr(
        "socket.gethostbyname",
        lambda host: (_ for _ in ()).throw(AssertionError("should not resolve")),
    )

    assert check_subdomains(_context("https://203.0.113.10/")) == []


def test_delay_is_applied_between_lookups(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("socket.gethostbyname", _fake_resolver(set()))
    slept: list[float] = []
    monkeypatch.setattr("vulnscan.checks.subdomains.time.sleep", slept.append)

    check_subdomains(_context("https://example.com/", delay=0.1))

    assert slept and all(s == 0.1 for s in slept)
