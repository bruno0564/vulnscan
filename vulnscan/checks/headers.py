"""Check de cabeceras: detecta cabeceras de seguridad ausentes y fugas de info."""

from ..types import Finding, Severity
from .base import ScanContext, register

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS — forces HTTPS",
    "X-Content-Type-Options": "Missing — allows MIME sniffing attacks",
    "X-Frame-Options": "Missing — clickjacking possible",
    "Content-Security-Policy": "Missing — XSS protection weakened",
    "Referrer-Policy": "Missing — leaks referrer info",
    "Permissions-Policy": "Missing — browser features unrestricted",
}

DANGEROUS_HEADERS = {
    "Server": "Exposes server software and version",
    "X-Powered-By": "Exposes backend technology",
    "X-AspNet-Version": "Exposes ASP.NET version",
}


@register
def check_headers(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    headers = ctx.response.headers

    for header, desc in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                {
                    "type": "missing_header",
                    "severity": Severity.MEDIUM,
                    "header": header,
                    "detail": desc,
                }
            )

    for header, desc in DANGEROUS_HEADERS.items():
        if header in headers:
            findings.append(
                {
                    "type": "info_disclosure",
                    "severity": Severity.LOW,
                    "header": header,
                    "value": headers[header],
                    "detail": desc,
                }
            )

    return findings
