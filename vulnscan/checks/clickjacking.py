"""Check de clickjacking: ¿se puede embeber la página en un <iframe> ajeno?

Una página es vulnerable a clickjacking si no restringe quién puede enmarcarla.
Hay dos mecanismos para impedirlo y basta con uno:

  - la cabecera `X-Frame-Options: DENY | SAMEORIGIN`, o
  - la directiva `frame-ancestors` dentro de `Content-Security-Policy` (la forma
    moderna, que sustituye a X-Frame-Options).

Solo se reporta si faltan AMBOS: comprobar únicamente X-Frame-Options daría
falsos positivos en sitios que ya se protegen vía CSP.
"""

from ..types import Finding, Severity
from .base import ScanContext, register

# Valores de X-Frame-Options que sí protegen. `ALLOW-FROM` está obsoleto y casi
# ningún navegador lo respeta, así que no lo consideramos protección válida.
_PROTECTIVE_XFO = {"deny", "sameorigin"}


@register
def check_clickjacking(ctx: ScanContext) -> list[Finding]:
    headers = ctx.response.headers

    xfo = headers.get("X-Frame-Options", "").strip().lower()
    if xfo in _PROTECTIVE_XFO:
        return []

    csp = headers.get("Content-Security-Policy", "").lower()
    if "frame-ancestors" in csp:
        return []

    return [
        {
            "type": "clickjacking",
            "severity": Severity.MEDIUM,
            "header": "X-Frame-Options",
            "detail": (
                "Page can be framed — no X-Frame-Options and no CSP "
                "frame-ancestors directive; clickjacking possible"
            ),
        }
    ]
