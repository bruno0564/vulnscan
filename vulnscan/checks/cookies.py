def check_cookies(response):
    findings = []

    for cookie in response.cookies:
        issues = []

        if not cookie.secure:
            issues.append("Secure flag missing — cookie sent over HTTP")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly flag missing — accessible via JavaScript")
        if not cookie.has_nonstandard_attr("SameSite"):
            issues.append("SameSite not set — CSRF risk")

        if issues:
            findings.append({
                "type": "insecure_cookie",
                "severity": "medium",
                "cookie": cookie.name,
                "issues": issues,
            })

    return findings
