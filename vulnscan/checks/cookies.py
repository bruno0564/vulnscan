import requests

from ..types import Finding


def check_cookies(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []

    for cookie in response.cookies:
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
                    "severity": "medium",
                    "cookie": cookie.name,
                    "issues": issues,
                }
            )

    return findings
