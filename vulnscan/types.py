"""Tipos compartidos por todo el escáner.

Un `Finding` es un hallazgo individual; `ScanResult` es el informe completo
que devuelve `scanner.scan()`. Usamos TypedDict (total=False) porque las claves
varían según el tipo de check, pero queremos que mypy valide las que sí están.
"""

from typing import TypedDict


class Finding(TypedDict, total=False):
    type: str  # identificador del hallazgo, p.ej. "missing_header"
    severity: str  # "high" | "medium" | "low"
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
