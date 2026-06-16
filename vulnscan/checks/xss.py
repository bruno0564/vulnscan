"""Check de XSS reflejado: inyecta un marcador en cada parámetro de la query y
comprueba si vuelve en la respuesta SIN escapar.

Es una detección de *reflexión*, no de ejecución: confirma que la entrada del
usuario llega al HTML con los metacaracteres (`< > " '`) intactos, que es la
condición necesaria para un XSS reflejado. No prueba que el navegador lo
ejecute, por eso el hallazgo es MEDIUM y no HIGH.

Solo actúa sobre parámetros ya presentes en la URL; si no hay query, no hay nada
que reflejar y el check no hace ninguna petición.
"""

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# Prefijo identificable + token aleatorio para no confundir el reflejo con
# contenido preexistente de la página. Los metacaracteres son los que importan:
# si vuelven sin codificar, el contexto es inyectable.
_MARKER_PREFIX = "vsxss"
_PAYLOAD_SUFFIX = "'\"<svg/onload=1>"


def _payload() -> str:
    return f"{_MARKER_PREFIX}{secrets.token_hex(4)}{_PAYLOAD_SUFFIX}"


@register
def check_xss(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    parsed = urlparse(ctx.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    for index, (name, _value) in enumerate(params):
        payload = _payload()
        injected = list(params)
        injected[index] = (name, payload)
        test_url = urlunparse(parsed._replace(query=urlencode(injected)))

        try:
            r = ctx.request("GET", test_url)
        except requests.RequestException:
            # Un parámetro que rompe la petición no debe abortar el resto.
            continue

        # Reflejo literal del payload (con `<`, `>`, comillas sin codificar) =
        # la entrada llega al HTML sin sanear.
        if payload in r.text:
            findings.append(
                {
                    "type": "reflected_xss",
                    "severity": Severity.MEDIUM,
                    "param": name,
                    "payload": payload,
                    "detail": (
                        f"Parameter '{name}' is reflected unescaped — possible reflected XSS"
                    ),
                }
            )

    return findings
