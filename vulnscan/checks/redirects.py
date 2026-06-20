"""Check de open redirect.

Si la aplicación redirige a una URL controlada por un parámetro sin validar el
destino, un atacante puede encadenar esa URL legítima para enviar a la víctima a
un sitio malicioso (phishing, robo de tokens en flujos OAuth…).

Inyectamos un destino externo conocido en los parámetros de redirección más
habituales y comprobamos si el servidor responde con un 3xx cuyo `Location`
apunta a ese dominio externo. No seguimos la redirección: solo miramos a dónde
nos quiere mandar.
"""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# Nombres de parámetro que suelen contener un destino de redirección.
REDIRECT_PARAMS = {
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redir",
    "return",
    "return_url",
    "returnurl",
    "returnto",
    "dest",
    "destination",
    "continue",
    "goto",
    "target",
    "rurl",
    "out",
}

# Destino de prueba. Si acabamos siendo redirigidos a este host, hay open redirect.
_EVIL = "https://evil.example.com/"
_EVIL_HOST = "evil.example.com"

# Si la URL no trae ningún parámetro de redirección, probamos a inyectar este
# pequeño núcleo de los más comunes en vez de los ~17, para no disparar
# demasiadas peticiones.
_PROBE_DEFAULTS = ("next", "url", "redirect", "returnurl")


def _redirects_to_evil(response: requests.Response) -> bool:
    if not response.is_redirect:  # 3xx con cabecera Location
        return False
    location = response.headers.get("Location", "")
    return urlparse(location).hostname == _EVIL_HOST


@register
def check_redirects(ctx: ScanContext) -> list[Finding]:
    parsed = urlparse(ctx.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)

    # Parámetros sospechosos ya presentes en la URL...
    candidates = {name for name, _ in params if name.lower() in REDIRECT_PARAMS}
    # ...o, si no hay ninguno, un núcleo de nombres comunes a inyectar.
    if not candidates:
        candidates = set(_PROBE_DEFAULTS)

    findings: list[Finding] = []
    for name in sorted(candidates):
        injected = [(n, v) for n, v in params if n != name]
        injected.append((name, _EVIL))
        test_url = urlunparse(parsed._replace(query=urlencode(injected)))

        try:
            response = ctx.request("GET", test_url, allow_redirects=False)
        except requests.RequestException:
            continue

        if _redirects_to_evil(response):
            findings.append(
                {
                    "type": "open_redirect",
                    "severity": Severity.MEDIUM,
                    "param": name,
                    "payload": _EVIL,
                    "detail": (
                        f"Parameter '{name}' redirects to an attacker-controlled "
                        "URL — open redirect"
                    ),
                }
            )

    return findings
