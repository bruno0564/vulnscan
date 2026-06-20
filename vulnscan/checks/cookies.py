"""Check de cookies: flags de seguridad ausentes (Secure, HttpOnly, SameSite)."""

from http.cookiejar import Cookie

from ..types import Finding, Severity
from .base import ScanContext, register


def _attrs_lower(cookie: Cookie) -> set[str]:
    """Atributos no estándar de la cookie (HttpOnly, SameSite…), en minúsculas.

    `http.cookiejar` guarda esos flags en `_rest` con la MISMA capitalización que
    mandó el servidor, y su `has_nonstandard_attr` compara de forma sensible a
    mayúsculas. Pero el RFC 6265 dice que los nombres de atributo son
    case-insensitive: un servidor puede mandar `httponly` o `SameSite=lax` y es
    igual de válido. Normalizamos a minúsculas para no reportar falsos positivos
    contra servidores que en realidad están bien configurados.
    """
    return {key.lower() for key in getattr(cookie, "_rest", {})}


@register
def check_cookies(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    for cookie in ctx.response.cookies:
        attrs = _attrs_lower(cookie)
        issues: list[str] = []

        if not cookie.secure:
            issues.append("Secure flag missing — cookie sent over HTTP")
        if "httponly" not in attrs:
            issues.append("HttpOnly flag missing — accessible via JavaScript")
        if "samesite" not in attrs:
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
