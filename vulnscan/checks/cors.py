"""Check de CORS: política Access-Control-* peligrosa (wildcard o reflexión)."""

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

PROBE_ORIGIN = "https://evil.com"


@register
def check_cors(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    try:
        r = ctx.session.options(
            ctx.url,
            headers={"Origin": PROBE_ORIGIN, "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
    except requests.RequestException:
        # Un fallo de red en este check no debe abortar el scan completo.
        return findings

    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")

    if acao == "*":
        findings.append(
            {
                "type": "cors_wildcard",
                "severity": Severity.MEDIUM,
                "detail": "ACAO: * — any origin can read responses",
            }
        )
    elif acao == PROBE_ORIGIN:
        severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
        findings.append(
            {
                "type": "cors_reflection",
                "severity": severity,
                "detail": f"Origin reflected back (ACAC: {acac or 'not set'})",
            }
        )

    return findings
