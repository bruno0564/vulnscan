"""Orquestador del escaneo: hace la petición principal y ejecuta los checks.

No conoce los checks concretos: los descubre desde el registro (`all_checks`),
de modo que añadir uno nuevo no requiere modificar este archivo.
"""

from urllib.parse import urlparse

import requests

from .checks import ScanContext, all_checks
from .types import SEVERITY_ORDER, Finding, ScanResult, Severity, Summary

USER_AGENT = "vulnscan/0.1 (security scanner)"


def scan(url: str) -> ScanResult:
    if not urlparse(url).scheme:
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    try:
        response = session.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        return {"error": str(e), "url": url, "findings": []}

    ctx = ScanContext(url=url, session=session, response=response)

    findings: list[Finding] = []
    for check in all_checks():
        findings += check(ctx)

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    summary: Summary = {
        "high": sum(1 for f in findings if f["severity"] == Severity.HIGH),
        "medium": sum(1 for f in findings if f["severity"] == Severity.MEDIUM),
        "low": sum(1 for f in findings if f["severity"] == Severity.LOW),
    }

    return {
        "url": response.url,
        "status": response.status_code,
        "findings": findings,
        "summary": summary,
    }
