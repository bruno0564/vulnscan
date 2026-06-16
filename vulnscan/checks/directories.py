"""Check de rutas expuestas: prueba paths sensibles comunes (.git, .env, admin…)."""

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# Cada path es una petición extra: muchas en serie pueden parecer abuso, por eso
# se canalizan por ctx.request(), que aplica el retardo de cortesía configurable.

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


@register
def check_directories(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    base = ctx.url.rstrip("/")

    for path in COMMON_PATHS:
        try:
            r = ctx.request("GET", f"{base}{path}", allow_redirects=False)
        except requests.RequestException:
            # Path inaccesible o timeout: lo ignoramos y seguimos con el resto.
            continue

        if r.status_code in (200, 403):
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
