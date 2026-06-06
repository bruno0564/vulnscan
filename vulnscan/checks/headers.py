import requests

from ..types import Finding

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


def check_headers(response: requests.Response) -> list[Finding]:
    findings: list[Finding] = []

    for header, desc in SECURITY_HEADERS.items():
        if header not in response.headers:
            findings.append(
                {
                    "type": "missing_header",
                    "severity": "medium",
                    "header": header,
                    "detail": desc,
                }
            )

    for header, desc in DANGEROUS_HEADERS.items():
        if header in response.headers:
            findings.append(
                {
                    "type": "info_disclosure",
                    "severity": "low",
                    "header": header,
                    "value": response.headers[header],
                    "detail": desc,
                }
            )

    return findings
