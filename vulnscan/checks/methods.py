"""Check de métodos HTTP peligrosos.

Pregunta al servidor qué métodos admite (vía `OPTIONS` y su cabecera `Allow`) y
reporta los que amplían la superficie de ataque si están habilitados sin
necesitarlos:

  - PUT / DELETE: permiten escribir o borrar recursos en el servidor.
  - TRACE / TRACK: habilitan Cross-Site Tracing (XST), que puede filtrar
    cabeceras sensibles aunque haya HttpOnly.
  - CONNECT: puede convertir el servidor en un proxy hacia otros destinos.

Es deliberadamente no destructivo: solo lee lo que el servidor *anuncia* con
OPTIONS, nunca llega a ejecutar un PUT o un DELETE reales.
"""

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# método -> motivo por el que es peligroso tenerlo habilitado.
DANGEROUS_METHODS: dict[str, str] = {
    "PUT": "allows uploading or overwriting resources",
    "DELETE": "allows deleting resources",
    "TRACE": "enables Cross-Site Tracing (XST)",
    "TRACK": "enables Cross-Site Tracing (XST)",
    "CONNECT": "can turn the server into a proxy",
    "PATCH": "allows partial modification of resources",
}


@register
def check_methods(ctx: ScanContext) -> list[Finding]:
    try:
        response = ctx.request("OPTIONS", ctx.url)
    except requests.RequestException:
        # Sin OPTIONS no podemos enumerar métodos; no es motivo para abortar.
        return []

    allow = response.headers.get("Allow", "")
    advertised = {method.strip().upper() for method in allow.split(",") if method.strip()}

    findings: list[Finding] = []
    for method, reason in DANGEROUS_METHODS.items():
        if method in advertised:
            findings.append(
                {
                    "type": "dangerous_method",
                    "severity": Severity.MEDIUM,
                    "method": method,
                    "detail": f"{method} enabled — {reason}",
                }
            )

    return findings
