"""Tipos compartidos por todo el escáner.

Un `Finding` es un hallazgo individual; `ScanResult` es el informe completo
que devuelve `scanner.scan()`. Usamos TypedDict (total=False) porque las claves
varían según el tipo de check, pero queremos que mypy valide las que sí están.
"""

from enum import Enum
from typing import TypedDict


class Severity(str, Enum):
    """Nivel de gravedad de un hallazgo.

    Hereda de `str` para que sea directamente serializable a JSON y comparable
    con cadenas, evitando strings mágicos ("high"/"medium"/"low") sueltos.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Orden de presentación en el informe (primero lo más grave).
SEVERITY_ORDER: dict[str, int] = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
}


class Finding(TypedDict, total=False):
    type: str  # identificador del hallazgo, p.ej. "missing_header"
    severity: str  # uno de los valores de Severity
    detail: str  # descripción legible
    header: str
    value: str
    path: str
    status: int
    cookie: str
    issues: list[str]


class Summary(TypedDict):
    high: int
    medium: int
    low: int


class ScanResult(TypedDict, total=False):
    url: str
    status: int
    findings: list[Finding]
    summary: Summary
    error: str
