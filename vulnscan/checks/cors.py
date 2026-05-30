import requests


def check_cors(url, session):
    findings = []

    try:
        r = session.options(
            url,
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append({
                "type": "cors_wildcard",
                "severity": "medium",
                "detail": "ACAO: * — any origin can read responses",
            })
        elif acao == "https://evil.com":
            severity = "high" if acac.lower() == "true" else "medium"
            findings.append({
                "type": "cors_reflection",
                "severity": severity,
                "detail": f"Origin reflected back (ACAC: {acac or 'not set'})",
            })
    except Exception:
        pass

    return findings
