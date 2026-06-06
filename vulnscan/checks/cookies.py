"""Check de cookies: flags de seguridad ausentes (Secure, HttpOnly, SameSite)."""

from ..types import Finding, Severity
from .base import ScanContext, register


@register
def check_cookies(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    for cookie in ctx.response.cookies:
        issues: list[str] = []

        if not cookie.secure:
            issues.append("Secure flag missing — cookie sent over HTTP")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly flag missing — accessible via JavaScript")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("SameSite not set — CSRF risk")

        if issues:
            findings.append(
                {
                    "type": "insecure_cookie",
                    "severity": Severity.MEDIUM,
                    "cookie": cookie.name,
                    "issues": issues,
                }
            )

    return findings
