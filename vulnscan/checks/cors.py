import requests

from ..types import Finding


def check_cors(url: str, session: requests.Session) -> list[Finding]:
    findings: list[Finding] = []

    try:
        r = session.options(
            url,
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            timeout=5,
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            findings.append(
                {
                    "type": "cors_wildcard",
                    "severity": "medium",
                    "detail": "ACAO: * — any origin can read responses",
                }
            )
        elif acao == "https://evil.com":
            severity = "high" if acac.lower() == "true" else "medium"
            findings.append(
                {
                    "type": "cors_reflection",
                    "severity": severity,
                    "detail": f"Origin reflected back (ACAC: {acac or 'not set'})",
                }
            )
    except requests.RequestException:
        # Un fallo de red en este check no debe abortar el scan completo.
        pass  # noqa: S110

    return findings
