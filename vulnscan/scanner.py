from urllib.parse import urlparse

import requests

from .checks.cookies import check_cookies
from .checks.cors import check_cors
from .checks.directories import check_directories
from .checks.headers import check_headers
from .types import Finding, ScanResult


def scan(url: str) -> ScanResult:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url

    session = requests.Session()
    session.headers["User-Agent"] = "vulnscan/0.1 (security scanner)"

    findings: list[Finding] = []

    try:
        response = session.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException as e:
        return {"error": str(e), "url": url, "findings": []}

    findings += check_headers(response)
    findings += check_cookies(response)
    findings += check_cors(url, session)
    findings += check_directories(url, session)

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    return {
        "url": response.url,
        "status": response.status_code,
        "findings": findings,
        "summary": {
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
        },
    }
