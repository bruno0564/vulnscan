"""Check de enumeración de subdominios.

Prueba un diccionario de prefijos comunes (www, mail, dev, api…) contra el
dominio del objetivo y reporta los que resuelven por DNS. Cada subdominio activo
amplía la superficie de ataque (entornos de staging, paneles, APIs internas…),
por eso se reportan como LOW/informativo.

La extracción del dominio base usa una heurística simple (las dos últimas
etiquetas), suficiente para dominios tipo `example.com`; no maneja sufijos
compuestos como `co.uk`. Las búsquedas DNS respetan el `--delay` configurado.
"""

import socket
import time
from urllib.parse import urlparse

from ..types import Finding, Severity
from .base import ScanContext, register

COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "sftp",
    "ns1",
    "ns2",
    "dns",
    "vpn",
    "remote",
    "portal",
    "secure",
    "gateway",
    "api",
    "api-dev",
    "dev",
    "develop",
    "staging",
    "stage",
    "test",
    "qa",
    "uat",
    "admin",
    "panel",
    "dashboard",
    "cpanel",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "blog",
    "shop",
    "store",
    "app",
    "apps",
    "mobile",
    "m",
    "beta",
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "files",
    "download",
    "backup",
    "support",
    "help",
    "docs",
    "wiki",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "db",
    "database",
    "sql",
    "redis",
    "internal",
    "intranet",
    "demo",
    "old",
]


def _base_domain(host: str) -> str | None:
    """Dominio registrable aproximado (dos últimas etiquetas).

    Devuelve `None` para IPs literales o hosts sin punto, donde no aplica
    enumerar subdominios.
    """
    host = host.split(":")[0]  # descartar puerto si lo hubiera
    parts = host.split(".")
    if len(parts) < 2 or all(part.isdigit() for part in parts):
        return None
    return ".".join(parts[-2:])


def _resolves(host: str) -> bool:
    """True si el host resuelve a una IP por DNS."""
    try:
        socket.gethostbyname(host)  # noqa: S110 — el resultado no se usa, solo si resuelve
    except OSError:
        return False
    return True


@register
def check_subdomains(ctx: ScanContext) -> list[Finding]:
    host = (urlparse(ctx.url).hostname or "").lower()
    base = _base_domain(host)
    if base is None:
        return []

    findings: list[Finding] = []
    for prefix in COMMON_SUBDOMAINS:
        candidate = f"{prefix}.{base}"
        if candidate == host:
            # No reportamos el propio objetivo como "subdominio descubierto".
            continue
        if ctx.delay > 0:
            time.sleep(ctx.delay)
        if _resolves(candidate):
            findings.append(
                {
                    "type": "subdomain",
                    "severity": Severity.LOW,
                    "host": candidate,
                    "detail": "Resolvable subdomain — expands attack surface",
                }
            )

    return findings
