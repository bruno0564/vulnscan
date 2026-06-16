"""Check de inyección SQL (básico, basado en errores).

Inyecta una comilla en cada parámetro de la query: si el valor llega sin sanear
a una consulta SQL, rompe la sintaxis y el motor suele filtrar un mensaje de
error reconocible. Buscamos esas firmas en la respuesta.

Para no marcar falsos positivos, se compara contra la respuesta original
(baseline): si el error ya estaba ahí sin inyectar nada, no se reporta.

Es probing básico (error-based), no explotación; pero un error de BBDD provocado
por una comilla es una señal fuerte, así que el hallazgo es HIGH.
"""

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from ..types import Finding, Severity
from .base import ScanContext, register

# La comilla simple es el payload clásico: cierra (o desbalancea) la cadena.
PROBE = "'"

# Firmas de error por motor. (regex, etiqueta legible).
DB_ERRORS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning: mysqli?_", re.I), "MySQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"microsoft (ole db|sql server|jet)|odbc .{0,20}driver", re.I), "MSSQL"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"ora-\d{5}", re.I), "Oracle"),
    (re.compile(r"(pg_query|pg_exec)\(\)|postgresql.{0,20}error", re.I), "PostgreSQL"),
    (re.compile(r"sqlite3?::|sqlite_error|sqlite.{0,20}syntax error", re.I), "SQLite"),
    (re.compile(r"sqlstate\[", re.I), "SQL"),
]


def _db_error(text: str) -> str | None:
    """Devuelve la etiqueta del motor si el texto contiene una firma de error."""
    for pattern, label in DB_ERRORS:
        if pattern.search(text):
            return label
    return None


@register
def check_sqli(ctx: ScanContext) -> list[Finding]:
    findings: list[Finding] = []

    parsed = urlparse(ctx.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return findings

    # Si la página ya muestra un error de BBDD sin que toquemos nada, cualquier
    # coincidencia posterior sería ruido: no podemos atribuirla a la inyección.
    baseline_has_error = _db_error(ctx.response.text) is not None

    for index, (name, value) in enumerate(params):
        payload = value + PROBE
        injected = list(params)
        injected[index] = (name, payload)
        test_url = urlunparse(parsed._replace(query=urlencode(injected)))

        try:
            r = ctx.request("GET", test_url)
        except requests.RequestException:
            continue

        db = _db_error(r.text)
        if db and not baseline_has_error:
            findings.append(
                {
                    "type": "sql_injection",
                    "severity": Severity.HIGH,
                    "param": name,
                    "payload": payload,
                    "detail": (
                        f"Parameter '{name}' triggers a {db} error — "
                        f"possible SQL injection"
                    ),
                }
            )

    return findings
