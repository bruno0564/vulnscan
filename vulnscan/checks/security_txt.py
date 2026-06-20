"""Check de security.txt (RFC 9116).

`security.txt` es un fichero estándar en `/.well-known/security.txt` donde una
organización publica cómo reportarle vulnerabilidades (contacto, política,
PGP…). Su ausencia no es una vulnerabilidad explotable, pero sí una señal de
madurez de seguridad: sin él, quien encuentre un fallo no sabe a quién avisar.
Se reporta como informativo (LOW).
"""

from urllib.parse import urlparse

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# Ubicación canónica (RFC 9116) y la heredada en la raíz, por compatibilidad.
_LOCATIONS = ("/.well-known/security.txt", "/security.txt")


@register
def check_security_txt(ctx: ScanContext) -> list[Finding]:
    parsed = urlparse(ctx.url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in _LOCATIONS:
        try:
            response = ctx.request("GET", f"{base}{path}", allow_redirects=True)
        except requests.RequestException:
            continue
        # Un security.txt válido es texto y contiene al menos un campo Contact:.
        if response.status_code == 200 and "contact:" in response.text.lower():
            return []  # existe y es válido -> nada que reportar

    return [
        {
            "type": "missing_security_txt",
            "severity": Severity.LOW,
            "path": "/.well-known/security.txt",
            "detail": "No security.txt — no documented channel to report vulnerabilities",
        }
    ]
