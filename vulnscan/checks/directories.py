"""Check de rutas expuestas: prueba paths sensibles comunes (.git, .env, admin…).

Algunos servidores responden 200 a CUALQUIER ruta (SPAs con catch-all, soft-404,
páginas comodín). Para no inundar de falsos positivos, primero se pide una ruta
aleatoria que casi seguro no existe: si el servidor también la da por buena, solo
se reportan los paths cuya respuesta DIFIERE de ese baseline.
"""

import secrets

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# Cada path es una petición extra: muchas en serie pueden parecer abuso, por eso
# se canalizan por ctx.request(), que aplica el retardo de cortesía configurable.

# Una respuesta se considera "distinta" del baseline si su tamaño difiere más de
# este porcentaje (además de comparar el status). 30% tolera plantillas de error
# con detalles variables sin perder páginas realmente distintas.
_SIZE_DIFF_THRESHOLD = 0.30

COMMON_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/backup.zip",
    "/backup.sql",
    "/admin",
    "/admin/",
    "/phpmyadmin",
    "/wp-admin",
    "/api/v1",
    "/swagger",
    "/swagger-ui.html",
    "/openapi.json",
    "/docs",
    "/actuator",
    "/actuator/env",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/debug",
]


def _differs(response: requests.Response, baseline: requests.Response) -> bool:
    """True si `response` es lo bastante distinta del baseline para ser real.

    Distinto status code ya es señal suficiente; con el mismo status, comparamos
    el tamaño del cuerpo: si es prácticamente igual, es la misma página comodín.
    """
    if response.status_code != baseline.status_code:
        return True
    a, b = len(response.content), len(baseline.content)
    if a == b:
        return False
    return abs(a - b) / max(a, b, 1) > _SIZE_DIFF_THRESHOLD


@register
def check_directories(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    base = ctx.url.rstrip("/")

    # Baseline: ruta aleatoria que no debería existir. Si responde 200/403, el
    # servidor es "catch-all" y no podemos fiarnos del status a secas.
    baseline: requests.Response | None = None
    try:
        baseline = ctx.request("GET", f"{base}/{secrets.token_hex(12)}", allow_redirects=False)
    except requests.RequestException:
        baseline = None
    catch_all = baseline is not None and baseline.status_code in (200, 403)

    for path in COMMON_PATHS:
        try:
            r = ctx.request("GET", f"{base}{path}", allow_redirects=False)
        except requests.RequestException:
            # Path inaccesible o timeout: lo ignoramos y seguimos con el resto.
            continue

        if r.status_code not in (200, 403):
            continue
        # En servidores catch-all, solo reportamos si difiere de la ruta basura.
        if catch_all and baseline is not None and not _differs(r, baseline):
            continue

        findings.append(
            {
                "type": "exposed_path",
                "severity": Severity.LOW if r.status_code == 403 else Severity.MEDIUM,
                "path": path,
                "status": r.status_code,
                "detail": f"HTTP {r.status_code}",
            }
        )

    return findings
