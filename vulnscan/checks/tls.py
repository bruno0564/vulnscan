"""Check de TLS / certificado.

Abre una conexión TLS al host y revisa dos cosas que un escáner web debería
mirar siempre:

  - el certificado: que sea válido (cadena de confianza, hostname) y que no esté
    caducado ni a punto de caducar, y
  - la versión de protocolo negociada: SSLv3 / TLS 1.0 / TLS 1.1 están obsoletos
    y rotos a efectos prácticos.

La lógica de evaluación (`_inspect`) está separada de la conexión de red para
poder testearla sin sockets reales.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..types import Finding, Severity
from .base import ScanContext, register

# Protocolos considerados débiles -> gravedad asociada.
_WEAK_PROTOCOLS: dict[str, Severity] = {
    "SSLv2": Severity.HIGH,
    "SSLv3": Severity.HIGH,
    "TLSv1": Severity.MEDIUM,
    "TLSv1.1": Severity.MEDIUM,
}

# Avisar si al certificado le quedan menos de estos días.
_EXPIRY_WARNING_DAYS = 15


def _inspect(protocol: str | None, not_after_epoch: float | None, *, now: float) -> list[Finding]:
    """Evalúa protocolo y caducidad. Función pura: sin red, fácil de testear."""
    findings: list[Finding] = []

    if protocol in _WEAK_PROTOCOLS:
        findings.append(
            {
                "type": "weak_tls_version",
                "severity": _WEAK_PROTOCOLS[protocol],
                "detail": f"Negotiated {protocol} — obsolete, upgrade to TLS 1.2+",
            }
        )

    if not_after_epoch is not None:
        days = (not_after_epoch - now) / 86400
        if days < 0:
            findings.append(
                {
                    "type": "expired_certificate",
                    "severity": Severity.HIGH,
                    "detail": f"TLS certificate expired {abs(int(days))} days ago",
                }
            )
        elif days < _EXPIRY_WARNING_DAYS:
            findings.append(
                {
                    "type": "expiring_certificate",
                    "severity": Severity.MEDIUM,
                    "detail": f"TLS certificate expires in {int(days)} days",
                }
            )

    return findings


def _connect(host: str, port: int, timeout: float) -> tuple[str | None, float | None]:
    """Negocia TLS y devuelve (versión de protocolo, caducidad del cert en epoch).

    Verifica la cadena y el hostname (contexto por defecto): si algo no cuadra,
    deja escapar `ssl.SSLCertVerificationError` para que el check lo reporte.
    """
    context = ssl.create_default_context()
    with (  # pragma: no cover
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls_sock,
    ):
        cert = tls_sock.getpeercert()
        protocol = tls_sock.version()
    not_after = cert.get("notAfter") if cert else None
    epoch = ssl.cert_time_to_seconds(not_after) if isinstance(not_after, str) else None
    return protocol, epoch


@register
def check_tls(ctx: ScanContext) -> list[Finding]:
    parsed = urlparse(ctx.url)
    if parsed.scheme != "https":
        return []  # sin TLS no hay nada que revisar aquí
    host = parsed.hostname
    if host is None:
        return []
    port = parsed.port or 443

    try:
        protocol, not_after = _connect(host, port, ctx.timeout)
    except ssl.SSLCertVerificationError as e:
        reason = getattr(e, "verify_message", None) or str(e)
        return [
            {
                "type": "invalid_certificate",
                "severity": Severity.HIGH,
                "host": host,
                "detail": f"TLS certificate failed verification: {reason}",
            }
        ]
    except (OSError, ssl.SSLError):
        # No se pudo establecer la conexión TLS (host caído, puerto cerrado…).
        return []

    now = datetime.now(timezone.utc).timestamp()
    return _inspect(protocol, not_after, now=now)
